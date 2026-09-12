import {AppRouteHandler, Request} from '@gravity-ui/expresskit';
import {AppError} from '@gravity-ui/nodekit';
import type {CallbackParamsType} from 'openid-client';
import requestIp from 'request-ip';

import {ApiTag} from '../../components/api-docs';
import {
    clearOidcTransactionCookie,
    getOidcTransactionCookie,
    setAuthCookie,
} from '../../components/cookies';
import {renderHtmlRedirectPage} from '../../components/html-redirect';
import {CONTENT_TYPE_HTML, CONTENT_TYPE_JSON} from '../../constants/content-type';
import {AUTH_ERROR} from '../../constants/error-constants';
import {USER_AGENT_HEADER} from '../../constants/header';
import {oidcCallback} from '../../services/auth/oidc';
import {errorModel, setCookieHeaderSchema} from '../reponse-models';

/**
 * Express may parse a repeated query parameter into an array, only plain string values are
 * meaningful for the authorization response.
 */
const getCallbackParams = (req: Request): CallbackParamsType => {
    return Object.entries(req.query).reduce<CallbackParamsType>((acc, [key, value]) => {
        if (typeof value === 'string') {
            acc[key] = value;
        }
        return acc;
    }, {});
};

export const oidcCallbackController: AppRouteHandler = async (req, res) => {
    const oidcTransaction = getOidcTransactionCookie(req);

    clearOidcTransactionCookie(req, res);

    if (!oidcTransaction) {
        throw new AppError('No oidc transaction cookie', {
            code: AUTH_ERROR.OIDC_INVALID_TRANSACTION,
        });
    }

    const {accessToken, refreshToken} = await oidcCallback(
        {ctx: req.ctx},
        {
            callbackParams: getCallbackParams(req),
            oidcTransaction,
            userAgent: req.headers[USER_AGENT_HEADER],
            userIp: requestIp.getClientIp(req),
        },
    );

    setAuthCookie({req, res, tokens: {accessToken, refreshToken}});

    // Not a 302: the auth cookies are `SameSite=Strict` by default and a browser would not send
    // them on a request that continues the redirect chain started by the identity provider.
    // A navigation started by this page comes from our own origin and is therefore same-site.
    res.status(200)
        .type(CONTENT_TYPE_HTML)
        .set('cache-control', 'no-store')
        .send(
            renderHtmlRedirectPage({
                url: req.ctx.config.uiAppEndpoint || '/',
                title: 'Continue to DataLens',
            }),
        );
};

oidcCallbackController.api = {
    summary: 'Finish SSO (OIDC) sign in',
    tags: [ApiTag.Auth],
    responses: {
        200: {
            description:
                'Sign in success, an html page that navigates the browser to the application',
            headers: setCookieHeaderSchema,
        },
        403: {
            description: 'The user is not a member of an allowed group',
            content: {
                [CONTENT_TYPE_JSON]: {
                    schema: errorModel.schema,
                },
            },
        },
    },
};
