import {AppError} from '@gravity-ui/nodekit';
import type {AppContext} from '@gravity-ui/nodekit';
import {Client, Issuer, custom} from 'openid-client';

import {AUTH_ERROR} from '../../../constants/error-constants';
import type {OidcConfig} from '../../../types/oidc';

const OIDC_HTTP_TIMEOUT = 10 * 1000;

custom.setHttpOptionsDefaults({timeout: OIDC_HTTP_TIMEOUT});

type CachedClient = {
    cacheKey: string;
    clientPromise: Promise<Client>;
};

let cachedClient: CachedClient | undefined;

export const assertOidcEnabled = (ctx: AppContext): OidcConfig => {
    const oidcConfig = ctx.config.oidc;

    if (!oidcConfig.enabled) {
        throw new AppError('OIDC is disabled', {code: AUTH_ERROR.OIDC_DISABLED});
    }

    const missingSettings = (
        [
            ['OIDC_ISSUER', oidcConfig.issuer],
            ['OIDC_CLIENT_ID', oidcConfig.clientId],
            ['OIDC_REDIRECT_URI', oidcConfig.redirectUri],
        ] as const
    )
        .filter(([, value]) => !value)
        .map(([name]) => name);

    if (missingSettings.length > 0) {
        throw new AppError(`OIDC is not configured: ${missingSettings.join(', ')} is empty`, {
            code: AUTH_ERROR.OIDC_MISCONFIGURED,
        });
    }

    return oidcConfig;
};

const makeCacheKey = (oidcConfig: OidcConfig) =>
    [oidcConfig.issuer, oidcConfig.clientId, oidcConfig.redirectUri].join('|');

const discoverClient = async (ctx: AppContext, oidcConfig: OidcConfig): Promise<Client> => {
    ctx.log('OIDC_DISCOVERY', {issuer: oidcConfig.issuer});

    const issuer = await Issuer.discover(oidcConfig.issuer);

    ctx.log('OIDC_DISCOVERY_SUCCESS');

    return new issuer.Client({
        client_id: oidcConfig.clientId,
        client_secret: oidcConfig.clientSecret || undefined,
        redirect_uris: [oidcConfig.redirectUri],
        response_types: ['code'],
        // Public clients (no secret configured) must not try to authenticate on the token endpoint
        token_endpoint_auth_method: oidcConfig.clientSecret ? undefined : 'none',
    });
};

/**
 * The discovery document is fetched once per process and cached.
 * A failed discovery is not cached, so the next request retries it.
 */
export const getOidcClient = async (ctx: AppContext): Promise<Client> => {
    const oidcConfig = assertOidcEnabled(ctx);
    const cacheKey = makeCacheKey(oidcConfig);

    if (!cachedClient || cachedClient.cacheKey !== cacheKey) {
        const clientPromise = discoverClient(ctx, oidcConfig);

        cachedClient = {cacheKey, clientPromise};

        clientPromise.catch(() => {
            if (cachedClient?.clientPromise === clientPromise) {
                cachedClient = undefined;
            }
        });
    }

    try {
        return await cachedClient.clientPromise;
    } catch (err) {
        ctx.logError('OIDC_DISCOVERY_ERROR', err);
        throw new AppError('Failed to load the OIDC discovery document', {
            code: AUTH_ERROR.OIDC_PROVIDER_UNAVAILABLE,
        });
    }
};

export const isPkceSupported = (client: Client): boolean => {
    const methods = client.issuer.metadata.code_challenge_methods_supported;

    return Array.isArray(methods) && methods.includes('S256');
};

/** Only for tests */
export const resetOidcClientCache = () => {
    cachedClient = undefined;
};
