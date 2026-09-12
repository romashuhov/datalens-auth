import {generators} from 'openid-client';

import type {OidcTransactionData} from '../../../types/oidc';
import type {ServiceArgs} from '../../../types/service';

import {getOidcClient, isPkceSupported} from './client';

export type StartOidcLoginResult = {
    authorizationUrl: string;
    transaction: OidcTransactionData;
};

export const startOidcLogin = async ({ctx}: ServiceArgs): Promise<StartOidcLoginResult> => {
    ctx.log('OIDC_LOGIN');

    const oidcConfig = ctx.config.oidc;
    const client = await getOidcClient(ctx);

    const state = generators.state();
    const nonce = generators.nonce();
    const codeVerifier = isPkceSupported(client) ? generators.codeVerifier() : undefined;

    const authorizationUrl = client.authorizationUrl({
        scope: oidcConfig.scopes,
        state,
        nonce,
        ...(codeVerifier
            ? {
                  code_challenge: generators.codeChallenge(codeVerifier),
                  code_challenge_method: 'S256',
              }
            : {}),
    });

    ctx.log('OIDC_LOGIN_REDIRECT', {pkce: Boolean(codeVerifier)});

    return {authorizationUrl, transaction: {state, nonce, codeVerifier}};
};
