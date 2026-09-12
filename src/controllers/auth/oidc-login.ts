import {AppRouteHandler} from '@gravity-ui/expresskit';

import {ApiTag} from '../../components/api-docs';
import {setOidcTransactionCookie} from '../../components/cookies';
import {CONTENT_TYPE_JSON} from '../../constants/content-type';
import {startOidcLogin} from '../../services/auth/oidc';
import {errorModel} from '../reponse-models';

export const oidcLoginController: AppRouteHandler = async (req, res) => {
    const {authorizationUrl, transaction} = await startOidcLogin({ctx: req.ctx});

    setOidcTransactionCookie({req, res, transaction});

    res.redirect(authorizationUrl);
};

oidcLoginController.api = {
    summary: 'Start SSO (OIDC) sign in',
    tags: [ApiTag.Auth],
    responses: {
        302: {
            description: 'Redirect to the identity provider',
        },
        404: {
            description: 'SSO (OIDC) is disabled',
            content: {
                [CONTENT_TYPE_JSON]: {
                    schema: errorModel.schema,
                },
            },
        },
    },
};
