import type {BigIntId} from '../../../db/types/id';

import {
    LocalLinkSkipReason,
    buildUserProfileFromClaims,
    checkGroupsAllowed,
    normalizeGroupsClaim,
    pickLocalLinkTarget,
    resolveLocalLinkAttempt,
} from './helpers';

const makeCandidate = (userId: string) => ({userId: userId as BigIntId});

describe('oidc helpers: normalizeGroupsClaim', () => {
    test('array of strings', () => {
        expect(normalizeGroupsClaim(['  dl-users ', 'dl-admins'])).toEqual([
            'dl-users',
            'dl-admins',
        ]);
    });

    test('array with non string items', () => {
        expect(normalizeGroupsClaim(['dl-users', 1, null, '', '   '])).toEqual(['dl-users']);
    });

    test('comma separated string', () => {
        expect(normalizeGroupsClaim('dl-users, DataLens Admins ')).toEqual([
            'dl-users',
            'DataLens Admins',
        ]);
    });

    test('single string with spaces is not split', () => {
        expect(normalizeGroupsClaim('DataLens Admins')).toEqual(['DataLens Admins']);
    });

    test('missing or unsupported claim', () => {
        expect(normalizeGroupsClaim(undefined)).toEqual([]);
        expect(normalizeGroupsClaim(null)).toEqual([]);
        expect(normalizeGroupsClaim(42)).toEqual([]);
        expect(normalizeGroupsClaim({})).toEqual([]);
    });
});

describe('oidc helpers: checkGroupsAllowed', () => {
    test('empty allowed list means no restriction', () => {
        expect(checkGroupsAllowed({allowedGroups: [], userGroups: []})).toBe(true);
        expect(checkGroupsAllowed({allowedGroups: [], userGroups: ['whatever']})).toBe(true);
    });

    test('intersection is allowed', () => {
        expect(
            checkGroupsAllowed({
                allowedGroups: ['dl-admins', 'dl-users'],
                userGroups: ['other', 'dl-users'],
            }),
        ).toBe(true);
    });

    test('no intersection is denied', () => {
        expect(checkGroupsAllowed({allowedGroups: ['dl-users'], userGroups: ['other']})).toBe(
            false,
        );
    });

    test('empty user groups with non empty allowed list is denied', () => {
        expect(checkGroupsAllowed({allowedGroups: ['dl-users'], userGroups: []})).toBe(false);
    });

    test('comparison is case sensitive', () => {
        expect(checkGroupsAllowed({allowedGroups: ['DL-Users'], userGroups: ['dl-users']})).toBe(
            false,
        );
    });
});

describe('oidc helpers: resolveLocalLinkAttempt', () => {
    test('disabled flag', () => {
        expect(
            resolveLocalLinkAttempt({
                enabled: false,
                email: 'user@example.com',
                emailVerified: true,
            }),
        ).toEqual({allowed: false, reason: LocalLinkSkipReason.Disabled});
    });

    test('no email claim', () => {
        expect(
            resolveLocalLinkAttempt({enabled: true, email: undefined, emailVerified: true}),
        ).toEqual({allowed: false, reason: LocalLinkSkipReason.NoEmail});
        expect(resolveLocalLinkAttempt({enabled: true, email: '  ', emailVerified: true})).toEqual({
            allowed: false,
            reason: LocalLinkSkipReason.NoEmail,
        });
    });

    test('email_verified=false blocks linking', () => {
        expect(
            resolveLocalLinkAttempt({
                enabled: true,
                email: 'user@example.com',
                emailVerified: false,
            }),
        ).toEqual({allowed: false, reason: LocalLinkSkipReason.EmailNotVerified});
        expect(
            resolveLocalLinkAttempt({
                enabled: true,
                email: 'user@example.com',
                emailVerified: 'false',
            }),
        ).toEqual({allowed: false, reason: LocalLinkSkipReason.EmailNotVerified});
    });

    test('absent email_verified does not block linking', () => {
        expect(
            resolveLocalLinkAttempt({
                enabled: true,
                email: ' User@Example.com ',
                emailVerified: undefined,
            }),
        ).toEqual({allowed: true, email: 'User@Example.com'});
    });

    test('verified email is allowed', () => {
        expect(
            resolveLocalLinkAttempt({
                enabled: true,
                email: 'user@example.com',
                emailVerified: true,
            }),
        ).toEqual({allowed: true, email: 'user@example.com'});
    });
});

describe('oidc helpers: pickLocalLinkTarget', () => {
    test('no matches', () => {
        expect(pickLocalLinkTarget([])).toEqual({
            found: false,
            reason: LocalLinkSkipReason.NoMatch,
        });
    });

    test('exactly one match', () => {
        const candidate = makeCandidate('1');
        expect(pickLocalLinkTarget([candidate])).toEqual({found: true, candidate});
    });

    test('two matches are ambiguous', () => {
        expect(pickLocalLinkTarget([makeCandidate('1'), makeCandidate('2')])).toEqual({
            found: false,
            reason: LocalLinkSkipReason.AmbiguousMatch,
        });
    });
});

describe('oidc helpers: buildUserProfileFromClaims', () => {
    test('full set of claims', () => {
        expect(
            buildUserProfileFromClaims({
                claims: {
                    preferred_username: 'j.doe',
                    email: 'j.doe@example.com',
                    given_name: 'John',
                    family_name: 'Doe',
                },
                emailClaim: 'email',
                sub: 'sub-1',
            }),
        ).toEqual({
            login: 'j.doe',
            email: 'j.doe@example.com',
            firstName: 'John',
            lastName: 'Doe',
        });
    });

    test('falls back to email and then to sub', () => {
        expect(
            buildUserProfileFromClaims({
                claims: {upn: 'j.doe@example.com'},
                emailClaim: 'upn',
                sub: 'sub-1',
            }),
        ).toEqual({
            login: 'j.doe@example.com',
            email: 'j.doe@example.com',
            firstName: null,
            lastName: null,
        });

        expect(buildUserProfileFromClaims({claims: {}, emailClaim: 'email', sub: 'sub-1'})).toEqual(
            {
                login: 'sub-1',
                email: null,
                firstName: null,
                lastName: null,
            },
        );
    });
});
