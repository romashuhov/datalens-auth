import {AppError} from '@gravity-ui/nodekit';
import {transaction} from 'objection';

import {JwtAuth} from '../../components/jwt-auth';
import {AUTH_ERROR} from '../../constants/error-constants';
import {DEV_IDP_SLUG, IdpType} from '../../constants/idp';
import {UserRole} from '../../constants/role';
import {RoleModel, RoleModelColumn} from '../../db/models/role';
import {UserModel, UserModelColumn} from '../../db/models/user';
import type {BigIntId} from '../../db/types/id';
import {getPrimary, getReplica} from '../../db/utils/db';
import {setCurrentTime} from '../../db/utils/query';
import type {ServiceArgs} from '../../types/service';
import type {Nullable, Optional} from '../../utils/utility-types';

export interface DevSigninArgs {
    email: string;
    editor: boolean;
    userAgent: Optional<string>;
    userIp: Nullable<string>;
}

/**
 * The email is the identity of a dev login user, so it is looked up by `idp_user_id` within the
 * `dev` idp only: local (`idp_type IS NULL`) and OIDC accounts are never touched by it.
 */
const findDevUser = async ({trx}: ServiceArgs, {email}: {email: string}) => {
    return UserModel.query(getReplica(trx))
        .select(UserModelColumn.UserId)
        .where({
            [UserModelColumn.IdpUserId]: email,
            [UserModelColumn.IdpSlug]: DEV_IDP_SLUG,
            [UserModelColumn.IdpType]: IdpType.Dev,
        })
        .first()
        .timeout(UserModel.DEFAULT_QUERY_TIMEOUT);
};

const createDevUser = async (
    {ctx, trx}: ServiceArgs,
    {email, editor}: {email: string; editor: boolean},
): Promise<BigIntId> => {
    const {getId} = ctx.get('registry').getDbInstance();
    const userId = await getId();

    await transaction(getPrimary(trx), async (transactionTrx) => {
        await UserModel.query(transactionTrx)
            .insert({
                [UserModelColumn.UserId]: userId,
                [UserModelColumn.Login]: email,
                [UserModelColumn.Email]: email,
                [UserModelColumn.FirstName]: email.split('@')[0],
                [UserModelColumn.LastName]: null,
                [UserModelColumn.IdpUserId]: email,
                [UserModelColumn.IdpSlug]: DEV_IDP_SLUG,
                [UserModelColumn.IdpType]: IdpType.Dev,
            })
            .timeout(UserModel.DEFAULT_QUERY_TIMEOUT);

        const roles = [editor ? UserRole.Editor : ctx.config.defaultRole].filter(Boolean);

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

    ctx.log('DEV_SIGNIN_USER_CREATED', {userId});

    return userId;
};

/** Roles are unique per (user, role), so granting a role the user already has changes nothing */
const grantEditorRole = async ({ctx, trx}: ServiceArgs, {userId}: {userId: BigIntId}) => {
    await RoleModel.query(getPrimary(trx))
        .insert({
            [RoleModelColumn.UserId]: userId,
            [RoleModelColumn.Role]: UserRole.Editor,
            [RoleModelColumn.UpdatedAt]: setCurrentTime(),
        })
        .onConflict([RoleModelColumn.UserId, RoleModelColumn.Role])
        .merge()
        .timeout(RoleModel.DEFAULT_QUERY_TIMEOUT);

    ctx.log('DEV_SIGNIN_EDITOR_ROLE_GRANTED', {userId});
};

export const devSignin = async ({ctx, trx}: ServiceArgs, args: DevSigninArgs) => {
    const {email, editor, userAgent, userIp} = args;

    ctx.log('DEV_SIGNIN');

    if (!ctx.config.devLoginEnabled) {
        throw new AppError('Dev login is disabled', {code: AUTH_ERROR.DEV_LOGIN_DISABLED});
    }

    const existingUser = await findDevUser({ctx, trx}, {email});
    const existingUserId = existingUser?.[UserModelColumn.UserId];

    const userId = existingUserId ?? (await createDevUser({ctx, trx}, {email, editor}));

    if (existingUserId && editor) {
        await grantEditorRole({ctx, trx}, {userId: existingUserId});
    }

    const {accessToken, refreshToken} = await JwtAuth.startSession(
        {ctx, trx},
        {userId, userAgent, userIp},
    );

    const {signinSuccess} = ctx.get('registry').common.functions.get();
    await signinSuccess({ctx, userId});

    ctx.log('DEV_SIGNIN_SUCCESS', {userId});

    return {accessToken, refreshToken};
};
