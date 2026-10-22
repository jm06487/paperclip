/**
 * End-to-end coverage for the admin-invite-only sign-up rule (MEC-690).
 *
 * Runs the real Better Auth mount against the real Drizzle schema and a
 * migrated embedded Postgres:
 *
 * - a no-token sign-up is refused with `EMAIL_PASSWORD_SIGN_UP_DISABLED` and
 *   writes no user/account/session rows;
 * - a valid, unexpired, single-use invite token completes exactly one human;
 * - the token cannot be reused, and expired, revoked, wrong-email, malformed,
 *   or already-accepted tokens are refused without a write;
 * - a token in the JSON body is ignored (the header is the only carrier);
 * - a failed sign-up leaves the invite usable;
 * - the admin invite route creates a working invite, the invited human signs
 *   up, accepts, and the owner approves the membership;
 * - sign-in and session still work for the account created by sign-up.
 */

import { randomUUID } from "node:crypto";
import express from "express";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  authAccounts,
  authSessions,
  authUsers,
  companies,
  companyMemberships,
  createDb,
  invites,
  joinRequests,
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
  let companyId!: string;
  let ownerId!: string;
  let actor: Record<string, unknown>;
  const originalEnv = {
    secret: process.env.BETTER_AUTH_SECRET,
    rateLimit: process.env.PAPERCLIP_AUTH_RATE_LIMIT_ENABLED,
  };

  function asOwner() {
    actor = {
      type: "board",
      userId: ownerId,
      source: "local_implicit",
      companyIds: [companyId],
      memberships: [{ companyId, membershipRole: "owner", status: "active" }],
      isInstanceAdmin: true,
    };
  }

  function asUser(userId: string) {
    actor = {
      type: "board",
      userId,
      source: "session",
      companyIds: [],
      memberships: [],
      isInstanceAdmin: false,
    };
  }

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
    acceptedAt?: Date | null;
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
        acceptedAt: input.acceptedAt ?? null,
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

    const company = await db
      .insert(companies)
      .values({
        name: "Invite Signup Co",
        issuePrefix: `IS${randomUUID().replace(/-/g, "").slice(0, 6).toUpperCase()}`,
      })
      .returning()
      .then((rows) => rows[0]!);
    companyId = company.id;
    ownerId = `owner-${randomUUID()}`;
    await db.insert(companyMemberships).values({
      companyId,
      principalType: "user",
      principalId: ownerId,
      status: "active",
      membershipRole: "owner",
    });
    asOwner();

    const auth = createBetterAuthInstance(db, testConfig(), [ORIGIN]);
    app = express();
    app.all("/api/auth/{*authPath}", createBetterAuthHandler(auth));
    app.use(express.json());
    app.use((req, _res, next) => {
      (req as any).actor = actor;
      next();
    });
    const { accessRoutes } = await import("../routes/access.js");
    app.use(
      "/api",
      accessRoutes(db, {
        deploymentMode: "authenticated",
        deploymentExposure: "private",
        bindHost: "127.0.0.1",
        allowedHostnames: [],
      }),
    );
    app.use((err: { status?: number; message?: string }, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      res.status(err.status ?? 500).json({ error: err.message ?? "Internal server error" });
    });
  }, 120_000);

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

  it("ignores an invite token in the JSON body", async () => {
    const token = "pcp_invite_body_token_0001";
    await insertInvite({ token, email: INVITED_EMAIL });

    const response = await signUp({
      email: INVITED_EMAIL,
      password: PASSWORD,
      name: "Body Token",
      inviteToken: token,
    });

    expect(response.status).toBe(400);
    expect(response.body?.code).toBe("EMAIL_PASSWORD_SIGN_UP_DISABLED");
    expect(await rowCounts()).toEqual({ users: 0, accounts: 0, sessions: 0 });
    const stored = (await db.select().from(invites)).find(
      (row) => row.tokenHash === hashInviteSignupToken(token),
    );
    expect(
      (stored?.defaultsPayload as Record<string, unknown> | null)?.signupConsumedAt,
    ).toBeUndefined();
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

  it("refuses malformed, expired, revoked, and already-accepted tokens", async () => {
    const malformed = await signUp(
      { email: INVITED_EMAIL, password: PASSWORD, name: "Malformed" },
      "not-a-real-invite-token",
    );
    expect(malformed.status).toBe(400);
    expect(malformed.body?.code).toBe("EMAIL_PASSWORD_SIGN_UP_DISABLED");

    const expiredToken = "pcp_invite_expired_token_0001";
    await insertInvite({
      token: expiredToken,
      email: "expired@example.com",
      expiresAt: new Date(Date.now() - 60_000),
    });
    const expired = await signUp(
      { email: "expired@example.com", password: PASSWORD, name: "Expired" },
      expiredToken,
    );
    expect(expired.status).toBe(400);
    expect(expired.body?.code).toBe("EMAIL_PASSWORD_SIGN_UP_DISABLED");

    const revokedToken = "pcp_invite_revoked_token_0001";
    await insertInvite({
      token: revokedToken,
      email: "revoked@example.com",
      revokedAt: new Date(),
    });
    const revoked = await signUp(
      { email: "revoked@example.com", password: PASSWORD, name: "Revoked" },
      revokedToken,
    );
    expect(revoked.status).toBe(400);
    expect(revoked.body?.code).toBe("EMAIL_PASSWORD_SIGN_UP_DISABLED");

    const acceptedToken = "pcp_invite_already_accepted_token_0001";
    await insertInvite({
      token: acceptedToken,
      email: "accepted@example.com",
      acceptedAt: new Date(),
    });
    const accepted = await signUp(
      { email: "accepted@example.com", password: PASSWORD, name: "Accepted" },
      acceptedToken,
    );
    expect(accepted.status).toBe(400);
    expect(accepted.body?.code).toBe("EMAIL_PASSWORD_SIGN_UP_DISABLED");

    expect(await rowCounts()).toEqual({ users: 0, accounts: 0, sessions: 0 });
  });

  it("leaves the invite usable after a failed sign-up", async () => {
    const token = "pcp_invite_failed_attempt_token_0001";
    const invite = await insertInvite({ token, email: INVITED_EMAIL });

    const failed = await signUp(
      { email: INVITED_EMAIL, password: "short", name: "Too Short" },
      token,
    );
    expect(failed.status).toBeGreaterThanOrEqual(400);
    expect(await rowCounts()).toEqual({ users: 0, accounts: 0, sessions: 0 });

    const stored = (await db.select().from(invites)).find((row) => row.id === invite.id);
    expect(
      (stored?.defaultsPayload as Record<string, unknown> | null)?.signupConsumedAt,
    ).toBeUndefined();

    const accepted = await signUp(
      { email: INVITED_EMAIL, password: PASSWORD, name: "Invitee" },
      token,
    );
    expect(accepted.status).toBe(200);
    expect(accepted.body?.user?.email).toBe(INVITED_EMAIL);
    expect(await rowCounts()).toEqual({ users: 1, accounts: 1, sessions: 1 });
  });

  it("signs in and reads the session for the account created by sign-up", async () => {
    const signIn = await request(app)
      .post("/api/auth/sign-in/email")
      .set("origin", ORIGIN)
      .send({ email: INVITED_EMAIL, password: PASSWORD });
    expect(signIn.status).toBe(200);

    const rawCookies = signIn.headers["set-cookie"];
    const cookies = Array.isArray(rawCookies) ? rawCookies : rawCookies ? [rawCookies] : [];
    const cookie = cookies.find((value) => value.includes("session_token"));
    expect(cookie).toBeDefined();
    const session = await request(app)
      .get("/api/auth/get-session")
      .set("origin", ORIGIN)
      .set("cookie", String(cookie).split(";", 1)[0]);
    expect(session.status).toBe(200);
    expect(session.body?.user?.email).toBe(INVITED_EMAIL);
  });

  it("creates an invite through the admin route, then completes and approves the human", async () => {
    asOwner();
    const created = await request(app)
      .post(`/api/companies/${companyId}/invites`)
      .set("origin", ORIGIN)
      .send({
        allowedJoinTypes: "human",
        humanRole: "operator",
        invitedEmail: "Admin-Invited@Example.com",
      });
    expect(created.status).toBe(201);
    expect(typeof created.body?.token).toBe("string");
    const token = created.body.token as string;
    const adminInvite = await db
      .select()
      .from(invites)
      .then((rows) => rows.find((row) => row.id === created.body?.id));
    expect(
      (adminInvite?.defaultsPayload as Record<string, unknown> | null)?.invitedEmail,
    ).toBe("admin-invited@example.com");

    const before = await rowCounts();
    const mismatch = await signUp(
      { email: OTHER_EMAIL, password: PASSWORD, name: "Mismatch" },
      token,
    );
    expect(mismatch.status).toBe(400);
    expect(mismatch.body?.code).toBe("EMAIL_PASSWORD_SIGN_UP_DISABLED");
    expect(await rowCounts()).toEqual(before);

    const accepted = await signUp(
      { email: "admin-invited@example.com", password: PASSWORD, name: "Admin Invited" },
      token,
    );
    expect(accepted.status).toBe(200);
    const userId = accepted.body?.user?.id as string;
    expect(typeof userId).toBe("string");

    const reuse = await signUp(
      { email: "admin-invited-2@example.com", password: PASSWORD, name: "Reuse" },
      token,
    );
    expect(reuse.status).toBe(400);
    expect(reuse.body?.code).toBe("EMAIL_PASSWORD_SIGN_UP_DISABLED");

    asUser(userId);
    const accept = await request(app)
      .post(`/api/invites/${token}/accept`)
      .set("origin", ORIGIN)
      .send({ requestType: "human" });
    expect(accept.status).toBe(202);

    const joinRequest = await db
      .select()
      .from(joinRequests)
      .then((rows) => rows.find((row) => row.requestingUserId === userId));
    expect(joinRequest?.status).toBe("approved");

    const membership = await db
      .select()
      .from(companyMemberships)
      .then((rows) => rows.find((row) => row.principalId === userId));
    expect(membership?.status).toBe("active");
  });
});
