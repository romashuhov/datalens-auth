import setCookieParser from 'set-cookie-parser';
import request from 'supertest';

import {getAuthCookieName, getAuthExpCookieName} from '../../../../../../components/cookies';
import {JwtAuth} from '../../../../../../components/jwt-auth';
import {SET_COOKIE_HEADER} from '../../../../../../constants/header';
import {DEV_IDP_SLUG, IdpType} from '../../../../../../constants/idp';
import {RoleModel, RoleModelColumn} from '../../../../../../db/models/role';
import {UserModel, UserModelColumn} from '../../../../../../db/models/user';
import {registry} from '../../../../../../registry';
import {AUTH_ERROR, UserRole, app, appConfig, appCtx} from '../../../../auth';
import {createTestUsers} from '../../../../helpers';
import {makeRoute} from '../../../../routes';

const initialDevLoginEnabled = appConfig.devLoginEnabled;

const devSignin = (email: unknown, editor?: boolean) =>
    request(app)
        .post(makeRoute('devSignin'))
        .send(typeof editor === 'boolean' ? {email, editor} : {email});

const getDevUserByEmail = (email: string) => {
    const {db} = registry.getDbInstance();

    return UserModel.query(db.primary)
        .where({
            [UserModelColumn.IdpUserId]: email,
            [UserModelColumn.IdpSlug]: DEV_IDP_SLUG,
        })
        .first();
};

const getUserRoles = async (userId: unknown) => {
    const {db} = registry.getDbInstance();

    const roles = await RoleModel.query(db.primary).where({[RoleModelColumn.UserId]: userId});

    return roles.map((role) => role[RoleModelColumn.Role]);
};

const getAuthCookies = (headers: Record<string, string>) =>
    setCookieParser
        .parse(headers[SET_COOKIE_HEADER] as unknown as string[])
        .filter((cookie) =>
            [getAuthCookieName(appCtx), getAuthExpCookieName(appCtx)].includes(cookie.name),
        );

describe('Dev sign in', () => {
    afterEach(() => {
        appConfig.devLoginEnabled = initialDevLoginEnabled;
    });

    test('The route is not available when the feature is disabled', async () => {
        appConfig.devLoginEnabled = false;

        const response = await devSignin('disabled@example.com');

        expect(response.status).toBe(404);
        expect(response.body.code).toBe(AUTH_ERROR.DEV_LOGIN_DISABLED);

        expect(await getDevUserByEmail('disabled@example.com')).toBeUndefined();
    });

    test('The first sign in creates a user with the default role and sets the auth cookies', async () => {
        appConfig.devLoginEnabled = true;

        const email = 'dev.new.user@example.com';

        const response = await devSignin(email);

        expect(response.status).toBe(200);

        const authCookies = getAuthCookies(response.header);

        expect(authCookies).toHaveLength(2);

        const createdUser = await getDevUserByEmail(email);

        expect(createdUser).toMatchObject({
            [UserModelColumn.Login]: email,
            [UserModelColumn.Email]: email,
            [UserModelColumn.FirstName]: 'dev.new.user',
            [UserModelColumn.LastName]: null,
            [UserModelColumn.IdpType]: IdpType.Dev,
            [UserModelColumn.IdpSlug]: DEV_IDP_SLUG,
            [UserModelColumn.Password]: null,
        });

        const accessToken = JSON.parse(
            authCookies.find((cookie) => cookie.name === getAuthCookieName(appCtx))?.value ?? '{}',
        ).accessToken as string;

        const payload = JwtAuth.verifyAccessToken({ctx: appCtx, accessToken});

        expect(payload.roles).toStrictEqual([appConfig.defaultRole]);
    });

    test('The second sign in with the same email reuses the same user', async () => {
        appConfig.devLoginEnabled = true;

        const email = 'dev.returning@example.com';

        expect((await devSignin(email)).status).toBe(200);

        const createdUser = await getDevUserByEmail(email);

        expect((await devSignin(email)).status).toBe(200);

        const {db} = registry.getDbInstance();
        const users = await UserModel.query(db.primary).where({
            [UserModelColumn.IdpUserId]: email,
            [UserModelColumn.IdpSlug]: DEV_IDP_SLUG,
        });

        expect(users).toHaveLength(1);
        expect(users[0][UserModelColumn.UserId]).toBe(createdUser?.[UserModelColumn.UserId]);
    });

    test('A different email gives a different user', async () => {
        appConfig.devLoginEnabled = true;

        expect((await devSignin('dev.first@example.com')).status).toBe(200);
        expect((await devSignin('dev.second@example.com')).status).toBe(200);

        const first = await getDevUserByEmail('dev.first@example.com');
        const second = await getDevUserByEmail('dev.second@example.com');

        expect(first?.[UserModelColumn.UserId]).toBeDefined();
        expect(second?.[UserModelColumn.UserId]).toBeDefined();
        expect(first?.[UserModelColumn.UserId]).not.toBe(second?.[UserModelColumn.UserId]);
    });

    test('The email is lower cased, so the case does not create a second user', async () => {
        appConfig.devLoginEnabled = true;

        expect((await devSignin('Dev.Mixed.Case@Example.com')).status).toBe(200);
        expect((await devSignin('dev.mixed.case@example.com')).status).toBe(200);

        const {db} = registry.getDbInstance();
        const users = await UserModel.query(db.primary).where({
            [UserModelColumn.IdpUserId]: 'dev.mixed.case@example.com',
            [UserModelColumn.IdpSlug]: DEV_IDP_SLUG,
        });

        expect(users).toHaveLength(1);
    });

    test('An existing local user with the same email is not linked', async () => {
        appConfig.devLoginEnabled = true;

        const email = 'dev.local.user@example.com';

        const localUser = await createTestUsers({login: 'dev-local-user', email});

        expect((await devSignin(email)).status).toBe(200);

        const devUser = await getDevUserByEmail(email);

        expect(devUser?.[UserModelColumn.UserId]).not.toBe(localUser[UserModelColumn.UserId]);
        expect(devUser?.[UserModelColumn.IdpType]).toBe(IdpType.Dev);
    });

    test('A user created with `editor` gets the editor role', async () => {
        appConfig.devLoginEnabled = true;

        const email = 'dev.editor@example.com';

        expect((await devSignin(email, true)).status).toBe(200);

        const createdUser = await getDevUserByEmail(email);

        expect(await getUserRoles(createdUser?.[UserModelColumn.UserId])).toStrictEqual([
            UserRole.Editor,
        ]);
    });

    test('`editor` adds the role to an existing user and a later sign in does not remove it', async () => {
        appConfig.devLoginEnabled = true;

        const email = 'dev.editor.later@example.com';

        expect((await devSignin(email)).status).toBe(200);

        const createdUser = await getDevUserByEmail(email);
        const userId = createdUser?.[UserModelColumn.UserId];

        expect(await getUserRoles(userId)).toStrictEqual([appConfig.defaultRole]);

        expect((await devSignin(email, true)).status).toBe(200);

        expect((await getUserRoles(userId)).sort()).toStrictEqual(
            [appConfig.defaultRole, UserRole.Editor].sort(),
        );

        // the same request twice must not add a duplicate
        expect((await devSignin(email, true)).status).toBe(200);
        expect(await getUserRoles(userId)).toHaveLength(2);

        // signing in without the flag keeps the roles as they are
        expect((await devSignin(email, false)).status).toBe(200);

        expect((await getUserRoles(userId)).sort()).toStrictEqual(
            [appConfig.defaultRole, UserRole.Editor].sort(),
        );
    });

    test('An invalid email is rejected', async () => {
        appConfig.devLoginEnabled = true;

        const response = await devSignin('not-an-email');

        expect(response.status).toBe(400);
        expect(response.body.code).toBe(AUTH_ERROR.VALIDATION_ERROR);
    });
});
