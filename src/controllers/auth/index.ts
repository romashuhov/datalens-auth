import {devSigninController} from './dev-signin';
import {logoutController} from './logout';
import {oidcCallbackController} from './oidc-callback';
import {oidcLoginController} from './oidc-login';
import {refreshController} from './refresh';
import {signinController} from './signin';
import {signupController} from './signup';

export default {
    signupController,
    logoutController,
    refreshController,
    signinController,
    devSigninController,
    oidcLoginController,
    oidcCallbackController,
};
