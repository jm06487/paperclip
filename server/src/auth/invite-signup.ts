import { createHash } from "node:crypto";
import { and, eq, gt, isNull, sql } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import { invites } from "@paperclipai/db";

/**
 * Header the invite landing page uses to present its invite token on the
 * Better Auth sign-up request. The token stays out of the JSON body so it is
 * not captured by body logging or echoed in validation errors.
 */
export const INVITE_SIGNUP_TOKEN_HEADER = "x-paperclip-invite-token";

const MAX_INVITE_TOKEN_LENGTH = 512;
const SIGNUP_CONSUMED_AT_KEY = "signupConsumedAt";

export type InviteSignupDecision =
  | { allowed: true; inviteId: string; companyId: string | null }
  | { allowed: false; reason: "missing" | "invalid" | "email_mismatch" };

/** Same digest `server/src/routes/access.ts` stores in `invites.tokenHash`. */
export function hashInviteSignupToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function readInviteSignupToken(input: {
  headers?: Headers | null;
}): string {
  const fromHeader = input.headers?.get(INVITE_SIGNUP_TOKEN_HEADER)?.trim();
  if (!fromHeader) return "";
  return fromHeader.length <= MAX_INVITE_TOKEN_LENGTH ? fromHeader : "";
}

function invitedEmailFromDefaults(defaultsPayload: unknown): string | null {
  if (!defaultsPayload || typeof defaultsPayload !== "object") return null;
  const value = (defaultsPayload as Record<string, unknown>).invitedEmail;
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  return normalized || null;
}

function normalizeEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  return normalized || null;
}

/**
 * Validate and atomically consume an invite token for a sign-up attempt.
 *
 * The token is single-use: the claim writes `signupConsumedAt` into
 * `invites.defaults_payload` in the same UPDATE that re-checks the invite is
 * still open, so two concurrent requests cannot both claim it. The normal
 * invite acceptance still writes `acceptedAt`, so the invite keeps its
 * existing lifecycle. When the invite carries `defaultsPayload.invitedEmail`,
 * the sign-up email must match it (case-insensitive). Company invites are
 * always bound to `companyId`.
 */
export async function claimInviteForSignup(
  db: Db,
  input: { token: string; email: unknown; now?: Date },
): Promise<InviteSignupDecision> {
  const token = input.token.trim();
  if (!token) return { allowed: false, reason: "missing" };

  const now = input.now ?? new Date();
  const tokenHash = hashInviteSignupToken(token);
  const [invite] = await db
    .select()
    .from(invites)
    .where(eq(invites.tokenHash, tokenHash))
    .limit(1);

  if (!invite) return { allowed: false, reason: "invalid" };
  if (invite.revokedAt || invite.acceptedAt) {
    return { allowed: false, reason: "invalid" };
  }
  if (invite.expiresAt.getTime() <= now.getTime()) {
    return { allowed: false, reason: "invalid" };
  }
  if (invite.inviteType !== "bootstrap_ceo" && invite.inviteType !== "company_join") {
    return { allowed: false, reason: "invalid" };
  }
  if (invite.inviteType === "company_join" && !invite.companyId) {
    return { allowed: false, reason: "invalid" };
  }
  if (invite.allowedJoinTypes !== "human" && invite.allowedJoinTypes !== "both") {
    return { allowed: false, reason: "invalid" };
  }
  const defaults = invite.defaultsPayload as Record<string, unknown> | null;
  if (defaults && typeof defaults === "object" && defaults[SIGNUP_CONSUMED_AT_KEY]) {
    return { allowed: false, reason: "invalid" };
  }

  const invitedEmail = invitedEmailFromDefaults(invite.defaultsPayload);
  if (invitedEmail) {
    const email = normalizeEmail(input.email);
    if (!email || email !== invitedEmail) {
      return { allowed: false, reason: "email_mismatch" };
    }
  }

  const consumedAt = now.toISOString();
  const [claimed] = await db
    .update(invites)
    .set({
      defaultsPayload: sql`jsonb_set(coalesce(${invites.defaultsPayload}, '{}'::jsonb), ARRAY[${SIGNUP_CONSUMED_AT_KEY}]::text[], to_jsonb(${consumedAt}::text), true)`,
      updatedAt: now,
    })
    .where(
      and(
        eq(invites.id, invite.id),
        isNull(invites.acceptedAt),
        isNull(invites.revokedAt),
        gt(invites.expiresAt, now),
        sql`coalesce(${invites.defaultsPayload} ->> ${SIGNUP_CONSUMED_AT_KEY}, '') = ''`,
      ),
    )
    .returning({ id: invites.id, companyId: invites.companyId });

  if (!claimed) return { allowed: false, reason: "invalid" };
  return { allowed: true, inviteId: claimed.id, companyId: claimed.companyId };
}

/**
 * Release a sign-up claim when Better Auth did not create the account.
 *
 * The `before` hook claims the invite so two concurrent sign-ups cannot both
 * pass, but a later failure (duplicate email, weak password, write error) must
 * not burn the admin-issued invite. The `after` hook calls this only for an
 * unsuccessful response; a claim is only ever held between those two hooks.
 */
export async function releaseInviteSignupClaim(
  db: Db,
  input: { token: string; now?: Date },
): Promise<boolean> {
  const token = input.token.trim();
  if (!token) return false;
  const now = input.now ?? new Date();
  const released = await db
    .update(invites)
    .set({
      defaultsPayload: sql`coalesce(${invites.defaultsPayload}, '{}'::jsonb) - ${SIGNUP_CONSUMED_AT_KEY}`,
      updatedAt: now,
    })
    .where(
      and(
        eq(invites.tokenHash, hashInviteSignupToken(token)),
        isNull(invites.acceptedAt),
        isNull(invites.revokedAt),
      ),
    )
    .returning({ id: invites.id });
  return released.length > 0;
}
