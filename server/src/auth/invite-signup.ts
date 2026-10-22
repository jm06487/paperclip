import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, randomUUID } from "node:crypto";
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
const SIGNUP_CLAIM_ID_KEY = "signupClaimId";
const SIGNUP_CLAIM_EXPIRES_AT_KEY = "signupClaimExpiresAt";

/**
 * A claimed invite is held only for a short window while Better Auth creates
 * the account. If the process dies before the claim is released, the expired
 * reservation becomes claimable again instead of burning the invite forever.
 */
export const INVITE_SIGNUP_CLAIM_TTL_MS = 10 * 60 * 1000;

/**
 * Request-scoped state shared by the Better Auth `before`/`after` hooks and the
 * HTTP handler wrapper. The claim id prevents one request from releasing a
 * different request's claim for the same token.
 */
export type InviteSignupClaimContext = { claimId?: string };
export const inviteSignupClaimContext = new AsyncLocalStorage<InviteSignupClaimContext>();

export type InviteSignupDecision =
  | { allowed: true; inviteId: string; companyId: string | null; claimId: string }
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
 * Validate and atomically reserve an invite token for a sign-up attempt.
 *
 * The token is single-use: the reservation writes `signupClaimId` and a short
 * `signupClaimExpiresAt` into `invites.defaults_payload` in the same UPDATE
 * that re-checks the invite is still open, so two concurrent requests cannot
 * both claim it. `signupConsumedAt` is written only after Better Auth created
 * the user, so a failed attempt can release the reservation without opening a
 * reuse window. The normal invite acceptance still writes `acceptedAt`, so the
 * invite keeps its existing lifecycle. When the invite carries
 * `defaultsPayload.invitedEmail`, the sign-up email must match it
 * (case-insensitive). Company invites are always bound to `companyId`.
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

  const claimId = randomUUID();
  const claimExpiresAt = new Date(now.getTime() + INVITE_SIGNUP_CLAIM_TTL_MS).toISOString();
  const [claimed] = await db
    .update(invites)
    .set({
      defaultsPayload: sql`coalesce(${invites.defaultsPayload}, '{}'::jsonb) || jsonb_build_object('signupClaimId', ${claimId}::text, 'signupClaimExpiresAt', ${claimExpiresAt}::text)`,
      updatedAt: now,
    })
    .where(
      and(
        eq(invites.id, invite.id),
        isNull(invites.acceptedAt),
        isNull(invites.revokedAt),
        gt(invites.expiresAt, now),
        sql`coalesce(${invites.defaultsPayload} ->> ${SIGNUP_CONSUMED_AT_KEY}, '') = ''`,
        sql`(
          coalesce(${invites.defaultsPayload} ->> ${SIGNUP_CLAIM_ID_KEY}, '') = ''
          or coalesce(${invites.defaultsPayload} ->> ${SIGNUP_CLAIM_EXPIRES_AT_KEY}, '') = ''
          or (${invites.defaultsPayload} ->> ${SIGNUP_CLAIM_EXPIRES_AT_KEY})::timestamptz <= ${now.toISOString()}::timestamptz
        )`,
      ),
    )
    .returning({ id: invites.id, companyId: invites.companyId });

  if (!claimed) return { allowed: false, reason: "invalid" };
  return { allowed: true, inviteId: claimed.id, companyId: claimed.companyId, claimId };
}

/**
 * Release a sign-up reservation when Better Auth did not create the account.
 *
 * The `before` hook reserves the invite so two concurrent sign-ups cannot both
 * pass, but a later failure (duplicate email, weak password, write error,
 * unexpected throw) must not burn the admin-issued invite. Only the request
 * that owns the reservation can release it.
 */
export async function releaseInviteSignupClaim(
  db: Db,
  input: { token: string; claimId: string; now?: Date },
): Promise<boolean> {
  const token = input.token.trim();
  const claimId = input.claimId.trim();
  if (!token || !claimId) return false;
  const now = input.now ?? new Date();
  const released = await db
    .update(invites)
    .set({
      defaultsPayload: sql`coalesce(${invites.defaultsPayload}, '{}'::jsonb) - ${SIGNUP_CLAIM_ID_KEY} - ${SIGNUP_CLAIM_EXPIRES_AT_KEY}`,
      updatedAt: now,
    })
    .where(
      and(
        eq(invites.tokenHash, hashInviteSignupToken(token)),
        isNull(invites.acceptedAt),
        isNull(invites.revokedAt),
        sql`${invites.defaultsPayload} ->> ${SIGNUP_CLAIM_ID_KEY} = ${claimId}`,
      ),
    )
    .returning({ id: invites.id });
  return released.length > 0;
}

/**
 * Mark a sign-up reservation as completed after Better Auth created the user.
 *
 * `signupConsumedAt` is the permanent success marker for the token, so a later
 * sign-up cannot use the invite again even after the reservation TTL expires.
 */
export async function completeInviteSignupClaim(
  db: Db,
  input: { token: string; claimId: string; now?: Date },
): Promise<boolean> {
  const token = input.token.trim();
  const claimId = input.claimId.trim();
  if (!token || !claimId) return false;
  const now = input.now ?? new Date();
  const completed = await db
    .update(invites)
    .set({
      defaultsPayload: sql`(coalesce(${invites.defaultsPayload}, '{}'::jsonb) - 'signupClaimId' - 'signupClaimExpiresAt') || jsonb_build_object('signupConsumedAt', ${now.toISOString()}::text)`,
      updatedAt: now,
    })
    .where(
      and(
        eq(invites.tokenHash, hashInviteSignupToken(token)),
        sql`${invites.defaultsPayload} ->> ${SIGNUP_CLAIM_ID_KEY} = ${claimId}`,
      ),
    )
    .returning({ id: invites.id });
  return completed.length > 0;
}
