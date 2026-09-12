import crypto from 'node:crypto';
import http from 'node:http';

import jwt from 'jsonwebtoken';

const KEY_ID = 'oidc-provider-mock-key';
const SIGN_ALGORITHM = 'RS256';

export type MockClaims = Record<string, unknown>;

export type TokenRequestRecord = {
    grantType?: string;
    code?: string;
    codeVerifier?: string;
    redirectUri?: string;
};

export type OidcProviderMock = {
    issuer: string;
    setNextClaims: (claims: MockClaims) => void;
    getLastTokenRequest: () => TokenRequestRecord | undefined;
    stop: () => Promise<void>;
};

const readBody = (req: http.IncomingMessage) =>
    new Promise<string>((resolve, reject) => {
        let body = '';
        req.on('data', (chunk) => {
            body += chunk;
        });
        req.on('end', () => resolve(body));
        req.on('error', reject);
    });

const sendJson = (res: http.ServerResponse, status: number, payload: unknown) => {
    const data = JSON.stringify(payload);
    res.writeHead(status, {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(data),
    });
    res.end(data);
};

/**
 * A minimal OIDC provider used by the integration tests: it serves a discovery document, a JWKS
 * with the public part of the test token key and a token endpoint that issues an id_token with
 * the claims the current test asked for.
 */
export const startOidcProviderMock = async ({
    port,
    clientId,
    privateKeyPem,
    publicKeyPem,
}: {
    port: number;
    clientId: string;
    privateKeyPem: string;
    publicKeyPem: string;
}): Promise<OidcProviderMock> => {
    const issuer = `http://127.0.0.1:${port}`;

    let nextClaims: MockClaims = {};
    let lastTokenRequest: TokenRequestRecord | undefined;

    const publicJwk = crypto.createPublicKey(publicKeyPem).export({format: 'jwk'});

    const discoveryDocument = {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        userinfo_endpoint: `${issuer}/userinfo`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ['code'],
        response_modes_supported: ['query'],
        grant_types_supported: ['authorization_code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: [SIGN_ALGORITHM],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        code_challenge_methods_supported: ['S256'],
        scopes_supported: ['openid', 'profile', 'email', 'groups'],
        claims_supported: ['sub', 'email', 'email_verified', 'groups'],
    };

    const server = http.createServer(async (req, res) => {
        const url = new URL(req.url ?? '/', issuer);

        try {
            switch (url.pathname) {
                case '/.well-known/openid-configuration': {
                    sendJson(res, 200, discoveryDocument);
                    return;
                }
                case '/jwks': {
                    sendJson(res, 200, {
                        keys: [{...publicJwk, kid: KEY_ID, use: 'sig', alg: SIGN_ALGORITHM}],
                    });
                    return;
                }
                case '/token': {
                    const body = new URLSearchParams(await readBody(req));

                    lastTokenRequest = {
                        grantType: body.get('grant_type') ?? undefined,
                        code: body.get('code') ?? undefined,
                        codeVerifier: body.get('code_verifier') ?? undefined,
                        redirectUri: body.get('redirect_uri') ?? undefined,
                    };

                    const now = Math.floor(Date.now() / 1000);

                    const idToken = jwt.sign(
                        {
                            iss: issuer,
                            aud: clientId,
                            iat: now,
                            exp: now + 300,
                            ...nextClaims,
                        },
                        privateKeyPem,
                        {algorithm: SIGN_ALGORITHM, keyid: KEY_ID},
                    );

                    sendJson(res, 200, {
                        access_token: 'mock-access-token',
                        token_type: 'Bearer',
                        expires_in: 300,
                        id_token: idToken,
                    });
                    return;
                }
                case '/userinfo': {
                    const {nonce: _nonce, ...userinfo} = nextClaims;
                    sendJson(res, 200, userinfo);
                    return;
                }
                default: {
                    sendJson(res, 404, {error: 'not_found'});
                }
            }
        } catch (err) {
            sendJson(res, 500, {error: 'server_error', message: String(err)});
        }
    });

    await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, '127.0.0.1', resolve);
    });

    return {
        issuer,
        setNextClaims: (claims: MockClaims) => {
            nextClaims = claims;
        },
        getLastTokenRequest: () => lastTokenRequest,
        stop: () =>
            new Promise<void>((resolve, reject) => {
                server.close((err) => (err ? reject(err) : resolve()));
            }),
    };
};
