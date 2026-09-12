import {AuthPolicy} from '@gravity-ui/expresskit';
import type {AppConfig} from '@gravity-ui/nodekit';

import {Feature, FeaturesConfig} from '../components/features/types';
import {MASTER_TOKEN_HEADER} from '../constants/header';
import {
    DEFAULT_OIDC_EMAIL_CLAIM,
    DEFAULT_OIDC_GROUPS_CLAIM,
    DEFAULT_OIDC_IDP_SLUG,
    DEFAULT_OIDC_SCOPES,
} from '../constants/idp';
import {UserRole} from '../constants/role';
import type {OidcConfig} from '../types/oidc';
import {
    getEnvCert,
    getEnvListVariable,
    getEnvTokenVariable,
    getEnvVariable,
    isTrueArg,
} from '../utils/env-utils';

export const features: FeaturesConfig = {
    [Feature.ReadOnlyMode]: false,
    [Feature.UseIpV6]: false,
};

const defaultRole = UserRole.Viewer;

const getOidcDefaultRole = (enabled: boolean): `${UserRole}` => {
    const role = getEnvVariable('OIDC_DEFAULT_ROLE');

    if (!role) {
        return defaultRole;
    }

    const knownRoles: string[] = Object.values(UserRole);

    if (enabled && !knownRoles.includes(role)) {
        throw new Error(
            `Unknown OIDC_DEFAULT_ROLE value '${role}', expected one of: ${knownRoles.join(', ')}`,
        );
    }

    return role as `${UserRole}`;
};

const oidcEnabled = isTrueArg(getEnvVariable('OIDC_ENABLED'));

const oidc: OidcConfig = {
    enabled: oidcEnabled,
    issuer: getEnvVariable('OIDC_ISSUER') ?? '',
    clientId: getEnvVariable('OIDC_CLIENT_ID') ?? '',
    clientSecret: getEnvVariable('OIDC_CLIENT_SECRET') ?? '',
    redirectUri: getEnvVariable('OIDC_REDIRECT_URI') ?? '',
    scopes: getEnvVariable('OIDC_SCOPES') ?? DEFAULT_OIDC_SCOPES,
    defaultRole: getOidcDefaultRole(oidcEnabled),
    groupsClaim: getEnvVariable('OIDC_GROUPS_CLAIM') ?? DEFAULT_OIDC_GROUPS_CLAIM,
    emailClaim: getEnvVariable('OIDC_EMAIL_CLAIM') ?? DEFAULT_OIDC_EMAIL_CLAIM,
    allowedGroups: getEnvListVariable('OIDC_ALLOWED_GROUPS'),
    linkLocalByEmail: isTrueArg(getEnvVariable('OIDC_LINK_LOCAL_BY_EMAIL')),
    idpSlug: getEnvVariable('OIDC_IDP_SLUG') ?? DEFAULT_OIDC_IDP_SLUG,
};

export default {
    appName: 'datalens-auth',

    appSocket: 'dist/run/server.sock',

    expressTrustProxyNumber: 3,
    expressBodyParserJSONConfig: {
        limit: '50mb',
    },
    expressBodyParserURLEncodedConfig: {
        limit: '50mb',
        extended: false,
    },

    appAuthPolicy: AuthPolicy.required,

    defaultRole,

    oidc,

    uiAppEndpoint: getEnvVariable('UI_APP_ENDPOINT'),
    authCookieEndpoint: getEnvVariable('AUTH_COOKIE_ENDPOINT'),
    authCookieName: getEnvVariable('AUTH_COOKIE_NAME'),
    disableWildcardCookie: isTrueArg(getEnvVariable('DISABLE_WILDCARD_COOKIE')),
    cookieSameSiteMode: getEnvVariable('COOKIE_SAME_SITE_MODE'),

    accessTokenTTL: 60 * 15, // 15 min
    refreshTokenTTL: 60 * 60 * 24 * 10, // 10 days
    sessionTTL: 60 * 60 * 24 * 30, // 30 days

    tokenPrivateKey: getEnvCert(process.env.TOKEN_PRIVATE_KEY as string),
    tokenPublicKey: getEnvCert(process.env.TOKEN_PUBLIC_KEY as string),

    appSensitiveKeys: [],
    appSensitiveHeaders: [MASTER_TOKEN_HEADER],

    masterToken: getEnvTokenVariable('MASTER_TOKEN'),

    swaggerEnabled: isTrueArg(getEnvVariable('SWAGGER_ENABLED')),

    manageLocalUsersDisabled: isTrueArg(getEnvVariable('AUTH_MANAGE_LOCAL_USERS_DISABLED')),
    signupDisabled: isTrueArg(getEnvVariable('AUTH_SIGNUP_DISABLED')),
    devLoginEnabled: isTrueArg(getEnvVariable('AUTH_DEV_LOGIN_ENABLED')),

    features,
} satisfies Partial<AppConfig>;
