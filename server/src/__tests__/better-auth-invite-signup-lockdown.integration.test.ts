/**
 * End-to-end coverage for the admin-invite-only sign-up rule (MEC-690).
 *
 * Runs the real Better Auth mount against the real Drizzle schema and a
 * migrated embedded Postgres:
 *
 * - a no-token sign-up is refused with `EMAIL_PASSWORD_SIGN_UP_DISABLED` and
 *   writes no user/account/session rows;
 * - a valid, unexpired, single-use invite token completes exactly one human;
 * - the token cannot be reused, and expired, revoked, or wrong-email tokens
 *   are refused without a write.
 */

import express from "express";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  authAccounts,
  authSessions,
  authUsers,
  createDb,
  invites,
} from "@paperclipai/db";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";
import { createBetterAuthHandler, createBetterAuthInstance } from "../auth/better-auth.js";
import { hashInviteSignupToken } from "../auth/invite-signup.js";
import type { Config } from "../config.js";

const ORIGIN = "http://127.0.0.1:41998";
const PASSWORD = "correct-horse-battery-staple";
const INVITED_EMAIL = "invitee@example.com";
const OTHER_EMAIL = "other@example.com";

const embeddedPostgresSupport = await getEmbeddedPostgresTestSupport();
const describeEmbeddedPostgres = embeddedPostgresSupport.supported ? describe : describe.skip;

function testConfig(): Config {
  return {
    deploymentMode: "authenticated",
    deploymentExposure: "private",
    authBaseUrlMode: "explicit",
    authPublicBaseUrl: ORIGIN,
    authDisableSignUp: true,
    allowedHostnames: ["127.0.0.1"],
    port: 41998,
  } as unknown as Config;
}

describeEmbeddedPostgres("Better Auth invite-only sign-up", () => {
  let database: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | null = null;
  let db!: ReturnType<typeof createDb>;
  let app!: express.Express;
  const originalEnv = {
    secret: process.env.BETTER_AUTH_SECRET,
    rateLimit: process.env.PAPERCLIP_AUTH_RATE_LIMIT_ENABLED,
  };

  async function rowCounts() {
    const [users, accounts, sessions] = await Promise.all([
      db.select().from(authUsers),
      db.select().from(authAccounts),
      db.select().from(authSessions),
    ]);
    return { users: users.length, accounts: accounts.length, sessions: sessions.length };
  }

  async function insertInvite(input: {
    token: string;
    email?: string | null;
    expiresAt?: Date;
    revokedAt?: Date | null;
  }) {
    const [row] = await db
      .insert(invites)
      .values({
        inviteType: "bootstrap_ceo",
        tokenHash: hashInviteSignupToken(input.token),
        allowedJoinTypes: "human",
        defaultsPayload: input.email ? { invitedEmail: input.email } : null,
        expiresAt: input.expiresAt ?? new Date(Date.now() + 60 * 60 * 1000),
        revokedAt: input.revokedAt ?? null,
      })
      .returning();
    return row;
  }

  function signUp(body: Record<string, unknown>, inviteToken?: string) {
    const req = request(app)
      .post("/api/auth/sign-up/email")
      .set("origin", ORIGIN)
      .send(body);
    if (inviteToken) req.set("X-Paperclip-Invite-Token", inviteToken);
    return req;
  }

  beforeAll(async () => {
    process.env.BETTER_AUTH_SECRET = "better-auth-secret-for-invite-signup-tests";
    process.env.PAPERCLIP_AUTH_RATE_LIMIT_ENABLED = "false";

    database = await startEmbeddedPostgresTestDatabase("paperclip-better-auth-invite-signup-");
    db = createDb(database.connectionString);

    const auth = createBetterAuthInstance(db, testConfig(), [ORIGIN]);
    app = express();
    app.all("/api/auth/{*authPath}", createBetterAuthHandler(auth));
  }, 30_000);

  afterAll(async () => {
    await database?.cleanup();
    if (originalEnv.secret === undefined) delete process.env.BETTER_AUTH_SECRET;
    else process.env.BETTER_AUTH_SECRET = originalEnv.secret;
    if (originalEnv.rateLimit === undefined) delete process.env.PAPERCLIP_AUTH_RATE_LIMIT_ENABLED;
    else process.env.PAPERCLIP_AUTH_RATE_LIMIT_ENABLED = originalEnv.rateLimit;
  });

  it("refuses a no-token sign-up and writes no rows", async () => {
    const response = await signUp({
      email: INVITED_EMAIL,
      password: PASSWORD,
      name: "No Token",
    });

    expect(response.status).toBe(400);
    expect(response.body?.code).toBe("EMAIL_PASSWORD_SIGN_UP_DISABLED");
    expect(await rowCounts()).toEqual({ users: 0, accounts: 0, sessions: 0 });
  });

  it("refuses a valid token when the sign-up email does not match the invite", async () => {
    const token = "pcp_invite_email_mismatch_token_0001";
    await insertInvite({ token, email: INVITED_EMAIL });

    const response = await signUp(
      { email: OTHER_EMAIL, password: PASSWORD, name: "Wrong Email" },
      token,
    );

    expect(response.status).toBe(400);
    expect(response.body?.code).toBe("EMAIL_PASSWORD_SIGN_UP_DISABLED");
    expect(await rowCounts()).toEqual({ users: 0, accounts: 0, sessions: 0 });
  });

  it("completes exactly one account for a valid invite, then refuses reuse", async () => {
    const token = "pcp_invite_single_use_token_0001";
    const invite = await insertInvite({ token, email: INVITED_EMAIL });

    const accepted = await signUp(
      { email: INVITED_EMAIL, password: PASSWORD, name: "Invitee" },
      token,
    );

    expect(accepted.status).toBe(200);
    expect(accepted.body?.user?.email).toBe(INVITED_EMAIL);
    expect(await rowCounts()).toEqual({ users: 1, accounts: 1, sessions: 1 });

    const [stored] = await db.select().from(invites);
    expect(stored.id).toBe(invite.id);
    expect(
      (stored.defaultsPayload as Record<string, unknown> | null)?.signupConsumedAt,
    ).toBeTruthy();

    const reused = await signUp(
      { email: OTHER_EMAIL, password: PASSWORD, name: "Reuse" },
      token,
    );
    expect(reused.status).toBe(400);
    expect(reused.body?.code).toBe("EMAIL_PASSWORD_SIGN_UP_DISABLED");
    expect(await rowCounts()).toEqual({ users: 1, accounts: 1, sessions: 1 });
  });

  it("refuses an expired invite token", async () => {
    const token = "pcp_invite_expired_token_0001";
    await insertInvite({
      token,
      email: "expired@example.com",
      expiresAt: new Date(Date.now() - 60_000),
    });

    const response = await signUp(
      { email: "expired@example.com", password: PASSWORD, name: "Expired" },
      token,
    );

    expect(response.status).toBe(400);
    expect(response.body?.code).toBe("EMAIL_PASSWORD_SIGN_UP_DISABLED");
    expect((await rowCounts()).users).toBe(1);
  });

  it("refuses a revoked invite token", async () => {
    const token = "pcp_invite_revoked_token_0001";
    await insertInvite({
      token,
      email: "revoked@example.com",
      revokedAt: new Date(),
    });

    const response = await signUp(
      { email: "revoked@example.com", password: PASSWORD, name: "Revoked" },
      token,
    );

    expect(response.status).toBe(400);
    expect(response.body?.code).toBe("EMAIL_PASSWORD_SIGN_UP_DISABLED");
    expect((await rowCounts()).users).toBe(1);
  });
});
