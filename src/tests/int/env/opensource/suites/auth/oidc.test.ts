import jwt from 'jsonwebtoken';
import setCookieParser from 'set-cookie-parser';
import request from 'supertest';

import {
    getAuthCookieName,
    getOidcTransactionCookieName,
} from '../../../../../../components/cookies';
import {JwtAuth} from '../../../../../../components/jwt-auth';
import {SET_COOKIE_HEADER} from '../../../../../../constants/header';
import {IdpType} from '../../../../../../constants/idp';
import {UserModel, UserModelColumn} from '../../../../../../db/models/user';
import {registry} from '../../../../../../registry';
import {resetOidcClientCache} from '../../../../../../services/auth/oidc';
import {AUTH_ERROR, UserRole, app, appConfig, appCtx} from '../../../../auth';
import {createTestUsers} from '../../../../helpers';
import {makeRoute} from '../../../../routes';
import {startOidcProviderMock} from '../../../../utils/oidc-provider-mock';

const OIDC_MOCK_PORT = 9979;

let idp = {} as Awaited<ReturnType<typeof startOidcProviderMock>>;

const initialOidcConfig = {...appConfig.oidc};

const restoreOidcConfig = () => {
    Object.assign(appConfig.oidc, initialOidcConfig);
};

const parseSetCookies = (header: unknown) => setCookieParser.parse(header as string[]);

type SignInArgs = {
    claims: Record<string, unknown>;
};

const signInWithOidc = async ({claims}: SignInArgs) => {
    const loginResponse = await request(app).get(makeRoute('oidcLogin'));

    expect(loginResponse.status).toBe(302);

    const authorizationUrl = new URL(loginResponse.header['location']);

    const transactionCookie = parseSetCookies(loginResponse.header[SET_COOKIE_HEADER]).find(
        (cookie) => cookie.name === getOidcTransactionCookieName(appCtx),
    );

    expect(transactionCookie).toBeDefined();

    const transaction = jwt.decode(transactionCookie?.value ?? '') as {
        state: string;
        nonce: string;
        codeVerifier?: string;
    };

    expect(authorizationUrl.searchParams.get('state')).toBe(transaction.state);
    expect(authorizationUrl.searchParams.get('nonce')).toBe(transaction.nonce);
    expect(authorizationUrl.searchParams.get('code_challenge_method')).toBe('S256');
    expect(authorizationUrl.searchParams.get('code_challenge')).toEqual(expect.any(String));
    expect(transaction.codeVerifier).toEqual(expect.any(String));

    idp.setNextClaims({nonce: transaction.nonce, ...claims});

    const callbackResponse = await request(app)
        .get(makeRoute('oidcCallback'))
        .query({code: 'mock-authorization-code', state: transaction.state})
        .set('Cookie', `${transactionCookie?.name}=${transactionCookie?.value}`);

    return {callbackResponse, authorizationUrl, transaction};
};

const getUserByIdpUserId = (idpUserId: string) => {
    const {db} = registry.getDbInstance();

    return UserModel.query(db.primary)
        .where({
            [UserModelColumn.IdpUserId]: idpUserId,
            [UserModelColumn.IdpSlug]: appConfig.oidc.idpSlug,
        })
        .first();
};

const getIssuedAccessToken = (headers: Record<string, string>) => {
    const authCookie = parseSetCookies(headers[SET_COOKIE_HEADER]).find(
        (cookie) => cookie.name === getAuthCookieName(appCtx),
    );

    expect(authCookie).toBeDefined();

    return JSON.parse(authCookie?.value ?? '{}').accessToken as string;
};

describe('OIDC sign in', () => {
    beforeAll(async () => {
        idp = await startOidcProviderMock({
            port: OIDC_MOCK_PORT,
            clientId: appConfig.oidc.clientId,
            privateKeyPem: appConfig.tokenPrivateKey,
            publicKeyPem: appConfig.tokenPublicKey,
        });

        resetOidcClientCache();
    });

    afterAll(async () => {
        await idp.stop();
        resetOidcClientCache();
    });

    afterEach(() => {
        restoreOidcConfig();
    });

    test('Callback without the transaction cookie is rejected', async () => {
        const response = await request(app)
            .get(makeRoute('oidcCallback'))
            .query({code: 'mock-authorization-code', state: 'unknown-state'});

        expect(response.status).toBe(400);
        expect(response.body.code).toBe(AUTH_ERROR.OIDC_INVALID_TRANSACTION);
    });

    test('Callback with a foreign state is rejected', async () => {
        const loginResponse = await request(app).get(makeRoute('oidcLogin'));

        const transactionCookie = parseSetCookies(loginResponse.header[SET_COOKIE_HEADER]).find(
            (cookie) => cookie.name === getOidcTransactionCookieName(appCtx),
        );

        const response = await request(app)
            .get(makeRoute('oidcCallback'))
            .query({code: 'mock-authorization-code', state: 'foreign-state'})
            .set('Cookie', `${transactionCookie?.name}=${transactionCookie?.value}`);

        expect(response.status).toBe(401);
        expect(response.body.code).toBe(AUTH_ERROR.OIDC_AUTHORIZATION_FAILED);
    });

    test('The first sign in creates a user with the default oidc role', async () => {
        const sub = 'oidc-sub-new-user';

        const {callbackResponse} = await signInWithOidc({
            claims: {
                sub,
                preferred_username: 'j.doe',
                email: 'j.doe@example.com',
                email_verified: true,
                given_name: 'John',
                family_name: 'Doe',
            },
        });

        // The success response is an html page, not a redirect, so that the `SameSite=Strict`
        // auth cookies are sent on the navigation that follows.
        expect(callbackResponse.status).toBe(200);
        expect(callbackResponse.header['content-type']).toContain('text/html');
        expect(callbackResponse.header['location']).toBeUndefined();
        expect(callbackResponse.text).toContain(`href="${appConfig.uiAppEndpoint || '/'}"`);
        expect(callbackResponse.text).toContain('http-equiv="refresh"');

        const createdUser = await getUserByIdpUserId(sub);

        expect(createdUser).toMatchObject({
            [UserModelColumn.Login]: 'j.doe',
            [UserModelColumn.Email]: 'j.doe@example.com',
            [UserModelColumn.FirstName]: 'John',
            [UserModelColumn.LastName]: 'Doe',
            [UserModelColumn.IdpType]: IdpType.Oidc,
            [UserModelColumn.IdpSlug]: appConfig.oidc.idpSlug,
            [UserModelColumn.Password]: null,
        });

        const accessToken = getIssuedAccessToken(callbackResponse.header);
        const payload = JwtAuth.verifyAccessToken({ctx: appCtx, accessToken});

        expect(payload.roles).toStrictEqual([appConfig.oidc.defaultRole]);

        // PKCE code verifier is sent to the token endpoint
        expect(idp.getLastTokenRequest()?.codeVerifier).toEqual(expect.any(String));
        expect(idp.getLastTokenRequest()?.grantType).toBe('authorization_code');
    });

    test('The second sign in reuses the same user', async () => {
        const sub = 'oidc-sub-returning-user';

        const first = await signInWithOidc({
            claims: {sub, preferred_username: 'returning', email: 'returning@example.com'},
        });
        expect(first.callbackResponse.status).toBe(200);

        const createdUser = await getUserByIdpUserId(sub);

        const second = await signInWithOidc({
            claims: {sub, preferred_username: 'returning', email: 'returning@example.com'},
        });
        expect(second.callbackResponse.status).toBe(200);

        const {db} = registry.getDbInstance();
        const users = await UserModel.query(db.primary).where({
            [UserModelColumn.IdpUserId]: sub,
        });

        expect(users).toHaveLength(1);
        expect(users[0][UserModelColumn.UserId]).toBe(createdUser?.[UserModelColumn.UserId]);
    });

    test('A user outside of the allowed groups gets 403 and is not created', async () => {
        appConfig.oidc.allowedGroups = ['dl-users'];

        const sub = 'oidc-sub-forbidden-group';

        const {callbackResponse} = await signInWithOidc({
            claims: {
                sub,
                preferred_username: 'outsider',
                email: 'outsider@example.com',
                groups: ['some-other-group'],
            },
        });

        expect(callbackResponse.status).toBe(403);
        expect(callbackResponse.body.code).toBe(AUTH_ERROR.OIDC_GROUP_NOT_ALLOWED);

        expect(await getUserByIdpUserId(sub)).toBeUndefined();
    });

    test('A user inside the allowed groups is signed in', async () => {
        appConfig.oidc.allowedGroups = ['dl-users', 'dl-admins'];

        const sub = 'oidc-sub-allowed-group';

        const {callbackResponse} = await signInWithOidc({
            claims: {
                sub,
                preferred_username: 'insider',
                email: 'insider@example.com',
                groups: ['some-other-group', 'dl-admins'],
            },
        });

        expect(callbackResponse.status).toBe(200);
        expect(await getUserByIdpUserId(sub)).toBeDefined();
    });

    test('An existing local user is linked by email when the flag is on', async () => {
        appConfig.oidc.linkLocalByEmail = true;

        const localUser = await createTestUsers({
            login: 'local-to-link',
            email: 'Local.To.Link@example.com',
            roles: [UserRole.Editor],
        });

        const sub = 'oidc-sub-linked-user';

        const {callbackResponse} = await signInWithOidc({
            claims: {
                sub,
                preferred_username: 'local.to.link',
                email: 'local.to.link@example.com',
                email_verified: true,
            },
        });

        expect(callbackResponse.status).toBe(200);

        const linkedUser = await getUserByIdpUserId(sub);

        expect(linkedUser?.[UserModelColumn.UserId]).toBe(localUser[UserModelColumn.UserId]);
        expect(linkedUser?.[UserModelColumn.Login]).toBe('local-to-link');
        expect(linkedUser?.[UserModelColumn.Password]).toBeNull();
        expect(linkedUser?.[UserModelColumn.IdpType]).toBe(IdpType.Oidc);

        // roles of the local account are kept
        const accessToken = getIssuedAccessToken(callbackResponse.header);
        const payload = JwtAuth.verifyAccessToken({ctx: appCtx, accessToken});
        expect(payload.roles).toStrictEqual([UserRole.Editor]);
    });

    test('An existing local user is not linked when the flag is off', async () => {
        appConfig.oidc.linkLocalByEmail = false;

        const localUser = await createTestUsers({
            login: 'local-not-to-link',
            email: 'local.not.to.link@example.com',
        });

        const sub = 'oidc-sub-not-linked-user';

        const {callbackResponse} = await signInWithOidc({
            claims: {
                sub,
                preferred_username: 'local.not.to.link',
                email: 'local.not.to.link@example.com',
                email_verified: true,
            },
        });

        expect(callbackResponse.status).toBe(200);

        const createdUser = await getUserByIdpUserId(sub);

        expect(createdUser?.[UserModelColumn.UserId]).not.toBe(localUser[UserModelColumn.UserId]);
        expect(createdUser?.[UserModelColumn.IdpType]).toBe(IdpType.Oidc);
    });

    test('A local user is not linked when the email is not verified', async () => {
        appConfig.oidc.linkLocalByEmail = true;

        const localUser = await createTestUsers({
            login: 'local-unverified-email',
            email: 'local.unverified@example.com',
        });

        const sub = 'oidc-sub-unverified-email';

        const {callbackResponse} = await signInWithOidc({
            claims: {
                sub,
                preferred_username: 'local.unverified',
                email: 'local.unverified@example.com',
                email_verified: false,
            },
        });

        expect(callbackResponse.status).toBe(200);

        const createdUser = await getUserByIdpUserId(sub);

        expect(createdUser?.[UserModelColumn.UserId]).not.toBe(localUser[UserModelColumn.UserId]);
    });

    test('An ambiguous email match is not linked', async () => {
        appConfig.oidc.linkLocalByEmail = true;

        await createTestUsers({login: 'ambiguous-1', email: 'ambiguous@example.com'});
        await createTestUsers({login: 'ambiguous-2', email: 'AMBIGUOUS@example.com'});

        const sub = 'oidc-sub-ambiguous-email';

        const {callbackResponse} = await signInWithOidc({
            claims: {
                sub,
                preferred_username: 'ambiguous',
                email: 'ambiguous@example.com',
                email_verified: true,
            },
        });

        expect(callbackResponse.status).toBe(200);

        const createdUser = await getUserByIdpUserId(sub);

        expect(createdUser?.[UserModelColumn.IdpType]).toBe(IdpType.Oidc);
        expect(createdUser?.[UserModelColumn.Login]).toBe('ambiguous');
    });

    test('OIDC routes are not available when the feature is disabled', async () => {
        appConfig.oidc.enabled = false;

        const response = await request(app).get(makeRoute('oidcLogin'));

        expect(response.status).toBe(404);
        expect(response.body.code).toBe(AUTH_ERROR.OIDC_DISABLED);
    });
});
