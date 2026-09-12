import type {BigIntId} from '../../../db/types/id';
import type {Nullable, Optional} from '../../../utils/utility-types';

export type OidcClaims = Record<string, unknown>;

/**
 * Group claim values are provider specific, so they are compared as is (case sensitive).
 * A claim may come as an array (Keycloak, Entra ID, ADFS) or as a single comma separated string.
 * Group names may contain spaces, so the string form is split by comma only.
 */
export const normalizeGroupsClaim = (value: unknown): string[] => {
    if (Array.isArray(value)) {
        return value.reduce<string[]>((acc, item) => {
            if (typeof item === 'string' && item.trim()) {
                acc.push(item.trim());
            }
            return acc;
        }, []);
    }

    if (typeof value === 'string') {
        return value
            .split(',')
            .map((item) => item.trim())
            .filter(Boolean);
    }

    return [];
};

/**
 * An empty `allowedGroups` list means that group membership is not restricted.
 */
export const checkGroupsAllowed = ({
    allowedGroups,
    userGroups,
}: {
    allowedGroups: string[];
    userGroups: string[];
}): boolean => {
    if (allowedGroups.length === 0) {
        return true;
    }

    const userGroupsSet = new Set(userGroups);

    return allowedGroups.some((group) => userGroupsSet.has(group));
};

export enum LocalLinkSkipReason {
    Disabled = 'LINK_LOCAL_BY_EMAIL_DISABLED',
    NoEmail = 'NO_EMAIL_CLAIM',
    EmailNotVerified = 'EMAIL_NOT_VERIFIED',
    NoMatch = 'NO_LOCAL_USER_WITH_SUCH_EMAIL',
    AmbiguousMatch = 'MORE_THAN_ONE_LOCAL_USER_WITH_SUCH_EMAIL',
}

export type LocalLinkAttempt =
    | {allowed: true; email: string}
    | {allowed: false; reason: LocalLinkSkipReason};

/**
 * Decides whether it is safe to look for an existing local account to link the idp identity to.
 * Linking by email is only allowed under an explicit flag and only for emails the provider did not
 * mark as unverified, otherwise an idp account could be used to take over a local account.
 */
export const resolveLocalLinkAttempt = ({
    enabled,
    email,
    emailVerified,
}: {
    enabled: boolean;
    email: Optional<string>;
    emailVerified: unknown;
}): LocalLinkAttempt => {
    if (!enabled) {
        return {allowed: false, reason: LocalLinkSkipReason.Disabled};
    }

    const normalizedEmail = typeof email === 'string' ? email.trim() : '';

    if (!normalizedEmail) {
        return {allowed: false, reason: LocalLinkSkipReason.NoEmail};
    }

    // An absent `email_verified` claim is treated as "not stated" and does not block linking,
    // an explicit falsy value does.
    if (emailVerified === false || emailVerified === 'false') {
        return {allowed: false, reason: LocalLinkSkipReason.EmailNotVerified};
    }

    return {allowed: true, email: normalizedEmail};
};

export type LocalLinkCandidate = {userId: BigIntId};

export type LocalLinkTarget<T extends LocalLinkCandidate> =
    | {found: true; candidate: T}
    | {found: false; reason: LocalLinkSkipReason};

/**
 * `auth_users` has no unique index on email, so linking is done only when the match is unambiguous.
 */
export const pickLocalLinkTarget = <T extends LocalLinkCandidate>(
    candidates: T[],
): LocalLinkTarget<T> => {
    if (candidates.length === 0) {
        return {found: false, reason: LocalLinkSkipReason.NoMatch};
    }

    if (candidates.length > 1) {
        return {found: false, reason: LocalLinkSkipReason.AmbiguousMatch};
    }

    return {found: true, candidate: candidates[0]};
};

export const getStringClaim = (claims: OidcClaims, claimName: string): Optional<string> => {
    const value = claims[claimName];

    if (typeof value === 'string' && value.trim()) {
        return value.trim();
    }

    return undefined;
};

export type OidcUserProfile = {
    login: string;
    email: Nullable<string>;
    firstName: Nullable<string>;
    lastName: Nullable<string>;
};

/**
 * `sub` is used as the last resort login because the login column is only informational
 * for idp users (the unique index on login covers local users only).
 */
export const buildUserProfileFromClaims = ({
    claims,
    emailClaim,
    sub,
}: {
    claims: OidcClaims;
    emailClaim: string;
    sub: string;
}): OidcUserProfile => {
    const email = getStringClaim(claims, emailClaim);

    return {
        login: getStringClaim(claims, 'preferred_username') ?? email ?? sub,
        email: email ?? null,
        firstName: getStringClaim(claims, 'given_name') ?? null,
        lastName: getStringClaim(claims, 'family_name') ?? null,
    };
};
