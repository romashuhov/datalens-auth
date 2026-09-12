export enum IdpType {
    Oidc = 'oidc',
    Dev = 'dev',
}

/** Both the slug and the idp user id of a password-less dev login user, see `AUTH_DEV_LOGIN_ENABLED` */
export const DEV_IDP_SLUG = 'dev';

export const DEFAULT_OIDC_IDP_SLUG = 'oidc';

export const DEFAULT_OIDC_SCOPES = 'openid profile email';

export const DEFAULT_OIDC_GROUPS_CLAIM = 'groups';

export const DEFAULT_OIDC_EMAIL_CLAIM = 'email';
