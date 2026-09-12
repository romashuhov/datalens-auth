import {Request, Response} from '@gravity-ui/expresskit';
import type {AppContext} from '@gravity-ui/nodekit';
import {AppError} from '@gravity-ui/nodekit';
import jwt from 'jsonwebtoken';

import {AUTH_DEFAULT_COOKIE_NAME} from '../constants/cookie';
import {AUTH_ERROR} from '../constants/error-constants';
import type {OidcTransactionData} from '../types/oidc';
import {AccessTokenPayload} from '../types/token';
import type {Optional} from '../utils/utility-types';

type Tokens = {accessToken: string; refreshToken: string};
type SameSite = boolean | 'lax' | 'strict' | 'none';

const OIDC_COOKIE_POSTFIX = 'oidc';
const OIDC_TRANSACTION_TTL_SEC = 60 * 10; // 10 min
const OIDC_TRANSACTION_TOKEN_ALGORITHM = 'PS256';

const LOCALHOST = ['localhost', '127.0.0.1', '[::1]'];
const LOCALHOST_WILDCARD = '.localhost'; // RFC-6761: https://www.rfc-editor.org/rfc/rfc6761.html#section-6.3
const ONE_HOUR = 60 * 60 * 1000;
const SAME_SITE_MODE = ['strict', 'lax', 'none'];

function isSubdomainOrEqual({domain, subdomain}: {domain: string; subdomain: string}): boolean {
    if (domain === subdomain) {
        return true;
    }
    return domain.endsWith(`.${subdomain}`);
}

export const generateCookieName = (ctx: AppContext, postfix?: string) => {
    const baseCookieName = ctx.config.authCookieName || AUTH_DEFAULT_COOKIE_NAME;
    return baseCookieName + (postfix ? `_${postfix}` : '');
};

export const getAuthCookieName = (ctx: AppContext) => generateCookieName(ctx);
export const getAuthExpCookieName = (ctx: AppContext) => generateCookieName(ctx, 'exp');

export const setAuthCookie = ({
    req,
    res,
    tokens,
}: {
    req: Request;
    res: Response;
    tokens: Tokens;
}) => {
    const ctx = req.ctx;
    const {accessToken, refreshToken} = tokens;
    const refreshTokenTTLSec = ctx.config.refreshTokenTTL;
    const maxAge = refreshTokenTTLSec * 1000 + ONE_HOUR;

    const baseCookieOptions = getBaseCookieOptions(req);

    res.cookie(
        getAuthCookieName(ctx),
        JSON.stringify({
            accessToken,
            refreshToken,
        }),
        {
            ...baseCookieOptions,
            httpOnly: true,
            maxAge,
        },
    );

    const {exp} = jwt.decode(accessToken) as AccessTokenPayload;

    res.cookie(getAuthExpCookieName(ctx), exp, {
        ...baseCookieOptions,
        httpOnly: false,
        maxAge,
    });
};

export const getAuthCookies = (req: Request) => {
    const ctx = req.ctx;
    const authCookie = req.cookies[getAuthCookieName(ctx)] as Optional<string>;
    const authExpCookie = req.cookies[getAuthExpCookieName(ctx)] as Optional<string>;

    let parsedAuthCookie: Optional<Tokens>;
    if (authCookie) {
        try {
            parsedAuthCookie = JSON.parse(authCookie) as Tokens;
        } catch (err) {
            req.ctx.logError('Failed to parse auth cookie', err);
        }
    }

    let parsedAuthExpCookie: Optional<number>;
    if (authExpCookie) {
        parsedAuthExpCookie = Number(authExpCookie);
    }

    return {
        authCookie: parsedAuthCookie,
        authExpCookie: parsedAuthExpCookie,
    };
};

export const getOidcTransactionCookieName = (ctx: AppContext) =>
    generateCookieName(ctx, OIDC_COOKIE_POSTFIX);

/**
 * The oidc transaction cookie is read on the request that the identity provider redirects to,
 * so it must not be `SameSite=Strict`, otherwise the browser will not send it back.
 */
function getOidcTransactionCookieOptions(req: Request) {
    const baseCookieOptions = getBaseCookieOptions(req);

    return {
        ...baseCookieOptions,
        sameSite: (baseCookieOptions.sameSite === 'none' ? 'none' : 'lax') as SameSite,
        httpOnly: true,
    };
}

export const setOidcTransactionCookie = ({
    req,
    res,
    transaction,
}: {
    req: Request;
    res: Response;
    transaction: OidcTransactionData;
}) => {
    const ctx = req.ctx;

    const token = jwt.sign(transaction, ctx.config.tokenPrivateKey, {
        algorithm: OIDC_TRANSACTION_TOKEN_ALGORITHM,
        expiresIn: `${OIDC_TRANSACTION_TTL_SEC}s`,
    });

    res.cookie(getOidcTransactionCookieName(ctx), token, {
        ...getOidcTransactionCookieOptions(req),
        maxAge: OIDC_TRANSACTION_TTL_SEC * 1000,
    });
};

export const getOidcTransactionCookie = (req: Request): Optional<OidcTransactionData> => {
    const ctx = req.ctx;
    const token = req.cookies[getOidcTransactionCookieName(ctx)] as Optional<string>;

    if (!token) {
        return undefined;
    }

    try {
        const payload = jwt.verify(token, ctx.config.tokenPublicKey, {
            algorithms: [OIDC_TRANSACTION_TOKEN_ALGORITHM],
        }) as OidcTransactionData;

        if (!payload.state || !payload.nonce) {
            return undefined;
        }

        return {
            state: payload.state,
            nonce: payload.nonce,
            codeVerifier: payload.codeVerifier,
        };
    } catch (err) {
        ctx.logError('Failed to parse oidc transaction cookie', err);
        return undefined;
    }
};

export const clearOidcTransactionCookie = (req: Request, res: Response) => {
    const cookieName = getOidcTransactionCookieName(req.ctx);

    res.clearCookie(cookieName, getOidcTransactionCookieOptions(req)).clearCookie(cookieName);
};

export const clearAuthCookies = (req: Request, res: Response) => {
    const ctx = req.ctx;
    const baseCookieOptions = getBaseCookieOptions(req);
    const authCookieName = getAuthCookieName(ctx);
    const authExpCookieName = getAuthExpCookieName(ctx);

    res.clearCookie(authCookieName, {
        ...baseCookieOptions,
        httpOnly: true,
    })
        .clearCookie(authExpCookieName, {...baseCookieOptions, httpOnly: false})
        .clearCookie(authCookieName) // without params for correct clear if any params was changed
        .clearCookie(authExpCookieName); // without params for correct clear if any params was changed
};

export function getBaseCookieOptions(req: Request) {
    const disableWildcardCookie = Boolean(req.ctx.config.disableWildcardCookie);
    const cookieSameSiteMode = req.ctx.config.cookieSameSiteMode;

    const uiAppEndpoint = req.ctx.config.uiAppEndpoint || '';
    const uiAppHostname = new URL(uiAppEndpoint, 'http://localhost').hostname;

    const authCookieEndpoint = req.ctx.config.authCookieEndpoint;
    let targetHostname = uiAppHostname;

    if (authCookieEndpoint) {
        const authCookieHostname = new URL(authCookieEndpoint, 'http://localhost').hostname;

        if (!isSubdomainOrEqual({domain: uiAppHostname, subdomain: authCookieHostname})) {
            throw new AppError(AUTH_ERROR.INVALID_AUTH_COOKIE_ENDPOINT, {
                code: AUTH_ERROR.INVALID_AUTH_COOKIE_ENDPOINT,
            });
        }

        targetHostname = authCookieHostname;
    }

    const isCookieWithoutDomain =
        LOCALHOST.includes(targetHostname) ||
        targetHostname.endsWith(LOCALHOST_WILDCARD) ||
        disableWildcardCookie;

    let originUrl: URL | undefined;

    if (req.headers.origin) {
        // check header origin for get real request domain and protocol
        originUrl = new URL(req.headers.origin, 'http://localhost');
    }

    const secure = Boolean(
        uiAppEndpoint ? uiAppEndpoint.startsWith('https') : originUrl?.protocol === 'https',
    );
    let domain = isCookieWithoutDomain ? undefined : targetHostname;

    if (
        disableWildcardCookie &&
        uiAppEndpoint &&
        originUrl?.hostname &&
        uiAppHostname !== originUrl?.hostname
    ) {
        // prevent set cookie to any domain, if uiAppEndpoint is set and uiAppEndpoint is not equal to hostname
        domain = uiAppHostname;
    }

    let sameSite: SameSite = true;
    if (cookieSameSiteMode && SAME_SITE_MODE.includes(cookieSameSiteMode)) {
        sameSite = cookieSameSiteMode as SameSite;
    }

    return {
        secure,
        path: '/',
        sameSite,
        domain,
    };
}
