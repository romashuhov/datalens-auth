import {AppRouteHandler, Response} from '@gravity-ui/expresskit';
import requestIp from 'request-ip';

import {ApiTag} from '../../components/api-docs';
import {setAuthCookie} from '../../components/cookies';
import {makeReqParser, z} from '../../components/zod';
import {CONTENT_TYPE_JSON} from '../../constants/content-type';
import {USER_AGENT_HEADER} from '../../constants/header';
import {devSignin} from '../../services/auth/dev-signin';
import {
    SuccessResponseModel,
    errorModel,
    setCookieHeaderSchema,
    successModel,
} from '../reponse-models';

const requestSchema = {
    body: z.object({
        email: z.string().trim().toLowerCase().email(),
        editor: z.boolean().optional().default(false),
    }),
};

const parseReq = makeReqParser(requestSchema);

export const devSigninController: AppRouteHandler = async (
    req,
    res: Response<SuccessResponseModel>,
) => {
    const {body} = await parseReq(req);

    const tokens = await devSignin(
        {ctx: req.ctx},
        {
            email: body.email,
            editor: body.editor,
            userIp: requestIp.getClientIp(req),
            userAgent: req.headers[USER_AGENT_HEADER],
        },
    );

    setAuthCookie({req, res, tokens});

    res.status(200).send(successModel.format());
};

devSigninController.api = {
    summary: 'Sign in by email without a password (development only)',
    tags: [ApiTag.Auth],
    request: {
        body: {
            content: {
                [CONTENT_TYPE_JSON]: {
                    schema: requestSchema.body,
                },
            },
        },
    },
    responses: {
        200: {
            description: 'Sign in success',
            content: {
                [CONTENT_TYPE_JSON]: {
                    schema: successModel.schema,
                },
            },
            headers: setCookieHeaderSchema,
        },
        404: {
            description: 'Password-less dev login is disabled',
            content: {
                [CONTENT_TYPE_JSON]: {
                    schema: errorModel.schema,
                },
            },
        },
    },
};
