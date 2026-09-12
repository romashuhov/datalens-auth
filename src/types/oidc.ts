import type {UserRole} from '../constants/role';

export interface OidcConfig {
    enabled: boolean;
    /** Issuer url, configuration is loaded from `<issuer>/.well-known/openid-configuration` */
    issuer: string;
    clientId: string;
    clientSecret: string;
    /** Must point to the publicly reachable callback url (usually the UI proxy path) */
    redirectUri: string;
    /** Space separated list of scopes */
    scopes: string;
    /** Role given to a user created by the first SSO sign in */
    defaultRole: `${UserRole}`;
    groupsClaim: string;
    emailClaim: string;
    /** Empty list means that group membership is not checked */
    allowedGroups: string[];
    /** Allows linking of an SSO identity to an existing local account with the same email */
    linkLocalByEmail: boolean;
    /** Value written to `auth_users.idp_slug` */
    idpSlug: string;
}

export type OidcTransactionData = {
    state: string;
    nonce: string;
    codeVerifier?: string;
};
