/* eslint-disable import/order */
import dotenv from 'dotenv';
dotenv.config();

import * as path from 'path';

import {NodeKit} from '@gravity-ui/nodekit';

import {getGatewayConfig} from './components/gateway';
import {schema} from './components/gateway/schema';
import {initDB} from './db/init-db';
import {registry} from './registry';

// Initialization order: nodekit -> db -> gateway -> expresskit
const nodekit = new NodeKit({
    configsPath: path.resolve(__dirname, 'configs'),
});

const {appName, appEnv, appInstallation, appDevMode} = nodekit.config;
nodekit.ctx.log('AppConfig details', {
    appName,
    appEnv,
    appInstallation,
    appDevMode,
});

if (nodekit.config.devLoginEnabled) {
    nodekit.ctx.logWarn(
        'AUTH_DEV_LOGIN_ENABLED is on: anybody can sign in as any user by email without a password. ' +
            'It is meant for local and test stacks only and must never be enabled in production.',
    );
}

const {dynamicFeaturesEndpoint} = nodekit.config;

if (dynamicFeaturesEndpoint) {
    nodekit.setupDynamicConfig('features', {
        url: dynamicFeaturesEndpoint,
    });
}

const initedDB = initDB(nodekit);
registry.setupDbInstance(initedDB);

registry.setupGateway(getGatewayConfig(nodekit), {root: schema});

export {nodekit};
