import {AppError} from '@gravity-ui/nodekit';
import {DBError} from 'db-errors';
import PG_ERROR from 'pg-error-constants';

import {AUTH_ERROR, READ_ONLY_MODE_CODE} from '../../constants/error-constants';

function getDBErrorCode(error: DBError): string {
    const nativeError = error.nativeError as Error & {code?: string};
    return nativeError?.code || '';
}

// eslint-disable-next-line complexity
export const prepareErrorResponse = (error: AppError | DBError) => {
    if (error instanceof DBError) {
        const dbCode = getDBErrorCode(error);
        switch (dbCode) {
            case PG_ERROR.UNIQUE_VIOLATION: {
                return {
                    code: 400,
                    response: {
                        code: AUTH_ERROR.DB_UNIQUE_VIOLATION,
                        message: 'The entity already exists',
                    },
                };
            }
            case PG_ERROR.NUMERIC_VALUE_OUT_OF_RANGE: {
                return {
                    code: 400,
                    response: {
                        code: AUTH_ERROR.NUMERIC_VALUE_OUT_OF_RANGE,
                        message: 'Wrong passed id',
                    },
                };
            }
            default:
                return {
                    code: 500,
                    response: {
                        message: 'Database error',
                    },
                };
        }
    }

    const {code, message, details} = error as AppError;

    switch (code) {
        case AUTH_ERROR.READ_ONLY_MODE_ENABLED: {
            return {
                code: READ_ONLY_MODE_CODE,
                response: {
                    code,
                },
            };
        }

        case AUTH_ERROR.VALIDATION_ERROR: {
            return {
                code: 400,
                response: {
                    code,
                    message,
                    details,
                },
            };
        }

        case AUTH_ERROR.USER_ALREADY_EXISTS: {
            return {
                code: 409,
                response: {
                    code,
                    message: 'The user already exists',
                },
            };
        }

        case AUTH_ERROR.USER_NOT_EXISTS: {
            return {
                code: 404,
                response: {
                    code,
                    message: "The user doesn't exist",
                },
            };
        }

        case AUTH_ERROR.OLD_PASSWORD_INCORRECT: {
            return {
                code: 400,
                response: {
                    code,
                    message: 'The old password is incorrect',
                },
            };
        }

        case AUTH_ERROR.ROLE_NOT_EXISTS: {
            return {
                code: 404,
                response: {
                    code,
                    message,
                },
            };
        }

        case AUTH_ERROR.NOT_CONSISTENT: {
            return {
                code: 400,
                response: {
                    code,
                    message,
                },
            };
        }

        case AUTH_ERROR.IDP_USER_CHANGE_NOT_ALLOWED: {
            return {
                code: 403,
                response: {
                    code,
                    message: 'Not allowed to change IdP user settings',
                },
            };
        }

        case AUTH_ERROR.MANAGE_LOCAL_USERS_DISABLED: {
            return {
                code: 403,
                response: {
                    code,
                    message: 'Local user management is disabled',
                },
            };
        }

        case AUTH_ERROR.SIGNUP_DISABLED: {
            return {
                code: 403,
                response: {
                    code,
                    message: 'Signup is disabled',
                },
            };
        }

        case AUTH_ERROR.INVALID_AUTH_COOKIE_ENDPOINT: {
            return {
                code: 400,
                response: {
                    code,
                    message:
                        'Auth cookie endpoint must be a subdomain of ui endpoint or equal to it',
                },
            };
        }

        case AUTH_ERROR.OIDC_DISABLED: {
            return {
                code: 404,
                response: {
                    code,
                    message: 'SSO (OIDC) is disabled',
                },
            };
        }

        case AUTH_ERROR.OIDC_MISCONFIGURED: {
            return {
                code: 500,
                response: {
                    code,
                    message: 'SSO (OIDC) is not configured properly',
                },
            };
        }

        case AUTH_ERROR.OIDC_PROVIDER_UNAVAILABLE: {
            return {
                code: 502,
                response: {
                    code,
                    message: 'The identity provider is unavailable',
                },
            };
        }

        case AUTH_ERROR.OIDC_INVALID_TRANSACTION: {
            return {
                code: 400,
                response: {
                    code,
                    message: 'The SSO sign in request is expired or invalid, please try again',
                },
            };
        }

        case AUTH_ERROR.OIDC_AUTHORIZATION_FAILED: {
            return {
                code: 401,
                response: {
                    code,
                    message: 'The identity provider rejected the sign in request',
                },
            };
        }

        case AUTH_ERROR.OIDC_INVALID_CLAIMS: {
            return {
                code: 400,
                response: {
                    code,
                    message,
                },
            };
        }

        case AUTH_ERROR.OIDC_GROUP_NOT_ALLOWED: {
            return {
                code: 403,
                response: {
                    code,
                    message:
                        'Access is denied: your account is not a member of a group allowed to sign in to DataLens',
                },
            };
        }

        case AUTH_ERROR.DEV_LOGIN_DISABLED: {
            return {
                code: 404,
                response: {
                    code,
                    message: 'Password-less dev login is disabled',
                },
            };
        }

        default:
            return {
                code: 500,
                response: {
                    message: 'Internal Server Error',
                },
            };
    }
};
