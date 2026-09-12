import {AppError} from '@gravity-ui/nodekit';
import type {AppContext} from '@gravity-ui/nodekit';
import {transaction} from 'objection';
import type {CallbackParamsType, Client, TokenSet} from 'openid-client';

import {JwtAuth} from '../../../components/jwt-auth';
import {AUTH_ERROR} from '../../../constants/error-constants';
import {IdpType} from '../../../constants/idp';
import {RoleModel, RoleModelColumn} from '../../../db/models/role';
import {UserModel, UserModelColumn} from '../../../db/models/user';
import type {BigIntId} from '../../../db/types/id';
import {getPrimary, getReplica} from '../../../db/utils/db';
import {lowerEqual, setCurrentTime} from '../../../db/utils/query';
import type {OidcConfig, OidcTransactionData} from '../../../types/oidc';
import type {ServiceArgs} from '../../../types/service';
import type {Nullable, Optional} from '../../../utils/utility-types';

import {assertOidcEnabled, getOidcClient} from './client';
import {
    LocalLinkSkipReason,
    type OidcClaims,
    buildUserProfileFromClaims,
    checkGroupsAllowed,
    getStringClaim,
    normalizeGroupsClaim,
    pickLocalLinkTarget,
    resolveLocalLinkAttempt,
} from './helpers';

export interface OidcCallbackArgs {
    callbackParams: CallbackParamsType;
    oidcTransaction: OidcTransactionData;
    userAgent: Optional<string>;
    userIp: Nullable<string>;
}

const exchangeCode = async ({
    ctx,
    client,
    oidcConfig,
    callbackParams,
    oidcTransaction,
}: {
    ctx: AppContext;
    client: Client;
    oidcConfig: OidcConfig;
    callbackParams: CallbackParamsType;
    oidcTransaction: OidcTransactionData;
}): Promise<TokenSet> => {
    try {
        return await client.callback(oidcConfig.redirectUri, callbackParams, {
            state: oidcTransaction.state,
            nonce: oidcTransaction.nonce,
            code_verifier: oidcTransaction.codeVerifier,
        });
    } catch (err) {
        ctx.logError('OIDC_CALLBACK_EXCHANGE_ERROR', err);
        throw new AppError('Failed to exchange the OIDC authorization code', {
            code: AUTH_ERROR.OIDC_AUTHORIZATION_FAILED,
        });
    }
};

/**
 * Not every provider puts groups or email into the id_token, so the userinfo endpoint is queried
 * when a claim we actually need is missing there.
 */
const enrichClaimsWithUserinfo = async ({
    ctx,
    client,
    oidcConfig,
    tokenSet,
    claims,
}: {
    ctx: AppContext;
    client: Client;
    oidcConfig: OidcConfig;
    tokenSet: TokenSet;
    claims: OidcClaims;
}): Promise<OidcClaims> => {
    const needGroups =
        oidcConfig.allowedGroups.length > 0 && claims[oidcConfig.groupsClaim] === undefined;
    const needEmail = claims[oidcConfig.emailClaim] === undefined;

    if (!needGroups && !needEmail) {
        return claims;
    }

    if (!client.issuer.metadata.userinfo_endpoint || !tokenSet.access_token) {
        return claims;
    }

    try {
        const userinfo = await client.userinfo(tokenSet);
        ctx.log('OIDC_USERINFO_SUCCESS');
        return {...claims, ...userinfo};
    } catch (err) {
        ctx.logError('OIDC_USERINFO_ERROR', err);
        return claims;
    }
};

const findUserByIdpId = async (
    {ctx, trx}: ServiceArgs,
    {sub, idpSlug}: {sub: string; idpSlug: string},
) => {
    const user = await UserModel.query(getReplica(trx))
        .select(UserModelColumn.UserId)
        .where({
            [UserModelColumn.IdpUserId]: sub,
            [UserModelColumn.IdpSlug]: idpSlug,
        })
        .first()
        .timeout(UserModel.DEFAULT_QUERY_TIMEOUT);

    if (user) {
        ctx.log('OIDC_EXISTING_IDP_USER_FOUND');
    }

    return user;
};

/**
 * Attaches the idp identity to an existing local account with the same email, keeping its user_id
 * (user_id is the author of collections/workbooks and the subject of access bindings).
 */
const tryLinkLocalUser = async (
    {ctx, trx}: ServiceArgs,
    {
        sub,
        email,
        oidcConfig,
    }: {
        sub: string;
        email: string;
        oidcConfig: OidcConfig;
    },
): Promise<Optional<BigIntId>> => {
    const candidates = await UserModel.query(getReplica(trx))
        .select(UserModelColumn.UserId)
        .where(UserModelColumn.IdpType, null)
        .where(lowerEqual({column: UserModelColumn.Email, value: email}))
        .limit(2)
        .timeout(UserModel.DEFAULT_QUERY_TIMEOUT);

    const target = pickLocalLinkTarget(candidates);

    if (!target.found) {
        ctx.log('OIDC_LINK_LOCAL_USER_SKIPPED', {reason: target.reason});
        return undefined;
    }

    const linkedUser = await UserModel.query(getPrimary(trx))
        .patch({
            [UserModelColumn.IdpUserId]: sub,
            [UserModelColumn.IdpSlug]: oidcConfig.idpSlug,
            [UserModelColumn.IdpType]: IdpType.Oidc,
            [UserModelColumn.Password]: null,
            [UserModelColumn.UpdatedAt]: setCurrentTime(),
        })
        .where({
            [UserModelColumn.UserId]: target.candidate[UserModelColumn.UserId],
            [UserModelColumn.IdpType]: null,
        })
        .returning(UserModelColumn.UserId)
        .first()
        .timeout(UserModel.DEFAULT_QUERY_TIMEOUT);

    if (!linkedUser) {
        ctx.log('OIDC_LINK_LOCAL_USER_SKIPPED', {reason: LocalLinkSkipReason.NoMatch});
        return undefined;
    }

    ctx.log('OIDC_LINK_LOCAL_USER_SUCCESS', {
        userId: linkedUser[UserModelColumn.UserId],
    });

    return linkedUser[UserModelColumn.UserId];
};

const createIdpUser = async (
    {ctx, trx}: ServiceArgs,
    {
        sub,
        claims,
        oidcConfig,
    }: {
        sub: string;
        claims: OidcClaims;
        oidcConfig: OidcConfig;
    },
): Promise<BigIntId> => {
    const {getId} = ctx.get('registry').getDbInstance();
    const userId = await getId();

    const {login, email, firstName, lastName} = buildUserProfileFromClaims({
        claims,
        emailClaim: oidcConfig.emailClaim,
        sub,
    });

    await transaction(getPrimary(trx), async (transactionTrx) => {
        await UserModel.query(transactionTrx)
            .insert({
                [UserModelColumn.UserId]: userId,
                [UserModelColumn.Login]: login,
                [UserModelColumn.Email]: email,
                [UserModelColumn.FirstName]: firstName,
                [UserModelColumn.LastName]: lastName,
                [UserModelColumn.IdpUserId]: sub,
                [UserModelColumn.IdpSlug]: oidcConfig.idpSlug,
                [UserModelColumn.IdpType]: IdpType.Oidc,
            })
            .timeout(UserModel.DEFAULT_QUERY_TIMEOUT);

        const roles = [oidcConfig.defaultRole].filter(Boolean);

        if (roles.length) {
            await RoleModel.query(transactionTrx)
                .insert(
                    roles.map((role) => ({
                        [RoleModelColumn.UserId]: userId,
                        [RoleModelColumn.Role]: role,
                    })),
                )
                .timeout(RoleModel.DEFAULT_QUERY_TIMEOUT);
        }
    });

    ctx.log('OIDC_USER_CREATED', {userId});

    return userId;
};

export const oidcCallback = async (
    {ctx, trx}: ServiceArgs,
    {callbackParams, oidcTransaction, userAgent, userIp}: OidcCallbackArgs,
) => {
    ctx.log('OIDC_CALLBACK');

    const oidcConfig = assertOidcEnabled(ctx);
    const client = await getOidcClient(ctx);

    const tokenSet = await exchangeCode({
        ctx,
        client,
        oidcConfig,
        callbackParams,
        oidcTransaction,
    });

    const idTokenClaims = tokenSet.claims() as OidcClaims;
    const sub = getStringClaim(idTokenClaims, 'sub');

    if (!sub) {
        throw new AppError('The id_token has no `sub` claim', {
            code: AUTH_ERROR.OIDC_INVALID_CLAIMS,
        });
    }

    const claims = await enrichClaimsWithUserinfo({
        ctx,
        client,
        oidcConfig,
        tokenSet,
        claims: idTokenClaims,
    });

    // The group check must happen before any write to the database
    const userGroups = normalizeGroupsClaim(claims[oidcConfig.groupsClaim]);

    if (!checkGroupsAllowed({allowedGroups: oidcConfig.allowedGroups, userGroups})) {
        ctx.logError('OIDC_GROUP_NOT_ALLOWED', null, {
            groupsClaim: oidcConfig.groupsClaim,
            userGroupsCount: userGroups.length,
        });
        throw new AppError('The user is not a member of an allowed group', {
            code: AUTH_ERROR.OIDC_GROUP_NOT_ALLOWED,
        });
    }

    const existingUser = await findUserByIdpId({ctx, trx}, {sub, idpSlug: oidcConfig.idpSlug});

    let userId = existingUser?.[UserModelColumn.UserId];

    if (!userId) {
        const linkAttempt = resolveLocalLinkAttempt({
            enabled: oidcConfig.linkLocalByEmail,
            email: getStringClaim(claims, oidcConfig.emailClaim),
            emailVerified: claims['email_verified'],
        });

        if (linkAttempt.allowed) {
            userId = await tryLinkLocalUser(
                {ctx, trx},
                {sub, email: linkAttempt.email, oidcConfig},
            );
        } else {
            ctx.log('OIDC_LINK_LOCAL_USER_SKIPPED', {reason: linkAttempt.reason});
        }
    }

    if (!userId) {
        userId = await createIdpUser({ctx, trx}, {sub, claims, oidcConfig});
    }

    const {accessToken, refreshToken} = await JwtAuth.startSession(
        {ctx, trx},
        {userId, userAgent, userIp},
    );

    const {signinSuccess} = ctx.get('registry').common.functions.get();
    await signinSuccess({ctx, userId});

    ctx.log('OIDC_CALLBACK_SUCCESS', {userId});

    return {accessToken, refreshToken, userId};
};
