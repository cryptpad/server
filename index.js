// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later
const { fork } = require('child_process');
const Crypto = require('crypto');
const Path = require('node:path');

const showHelp = () => {
    console.log(`Usage ${process.argv[1]}:`);
    console.log("\t--help, -h\tDisplay this help");
    console.log("\t--type,-t\tSet the node type (if unset, starts every node)");
    console.log("\t--index,-i\tSet the node index (default: 0)");
    console.log("\t--server,-s\tStart the set of nodes identified with serverId");
    process.exit(1);
};

const args = process.argv.slice(2);
const cliArgs = {};
let prev;
args.some(arg => {
    if (arg === '--type' || arg === '-t') {
        if (prev) { throw new Error('INVALID ARGS');}
        prev = 'type';
        return;
    }
    if (arg === '--index' || arg === '-i') {
        if (prev) { throw new Error('INVALID ARGS');}
        prev = 'index';
        return;
    }
    if (arg === '--server' || arg === '-s') {
        if (prev) { throw new Error('INVALID ARGS');}
        prev = 'server';
        return;
    }
    if (arg === '--help' || arg === '-h') {
        showHelp();
        return true;
    }
    if (/^--?/.test(arg)) {
        prev = '';
        return;
    }

    if (!prev) { return; }
    cliArgs[prev] = arg;
    prev = '';
});

// Clean quit: kill child processes
const childPids = new Set();

const cleanSubprocesses = () => Array.from(childPids).forEach((pid) => {
    try {
        process.kill(pid);
    } catch (e) {
        if (e.code === 'ESRCH') { return; }
        console.error(e);
    }
});

process.on('SIGTERM', cleanSubprocesses);
process.on('exit', cleanSubprocesses);

const start = (serverConfig, infraConfig) => {
    const Log = {
        debug: console.debug,
        error: console.error,
        info: console.log,
        verbose: console.info,
        warn: console.warn
    };

    let serverId;
    const startNode = (type, index, forking) => new Promise((resolve, reject) => {
        const nodeFile = './build/' + type + '.js';
        const path = Path.join(__dirname, nodeFile);
        const initConfig = {
            myId: `${type}:${index}`,
            index,
            config: serverConfig,
            infra: infraConfig
        };

        //Log.info(`Starting: ${initConfig.myId}`);
        if (forking) {
            let nodeProcess = fork(path);
            childPids.add(nodeProcess.pid);
            nodeProcess.send(initConfig);
            nodeProcess.on('message', (message) => {
                if (message.msg === 'READY') {
                    // Log.info(`Started: ${type}:${message.index}`);
                    if (message.dev) {
                        Log.info('DEV mode enabled');
                    }
                    resolve();
                }
            });
            nodeProcess.on('error', (err) => {
                Log.error('Child process stopped due to error.');
                Log.error(err);
                reject(`${type}:${index}: error ${err}`);
                if (childPids.has(nodeProcess.pid)) { childPids.delete(nodeProcess.pid); }
                process.exit(1);
            });
            nodeProcess.on('exit', (err) => {
                if (err) {
                    Log.error('Child process stopped due to error.');
                    Log.error(err);
                }
                reject(`${type}:${index}: exit(${err})`);
                if (childPids.has(nodeProcess.pid)) { childPids.delete(nodeProcess.pid); }
                process.exit(err);
            });
        } else {
            // Single process start
            // Can only be called from CLI and not from external module
            require(path).start(initConfig);
        }
    });

    const coresReady = () => {
        const promises = [];
        infraConfig?.front?.forEach((data, index) => {
          if (serverId && data.serverId !== serverId) { return; }
          promises.push(startNode('front', index, true));
        });
        infraConfig?.storage?.forEach((data, index) => {
          if (serverId && data.serverId !== serverId) { return; }
            promises.push(startNode('storage', index, true));
        });
      if (serverId && infraConfig?.public?.httpServerId !== serverId) { return; }
        promises.push(startNode('http', 0, true));
        return Promise.all(promises.filter(Boolean)).then(() => {
            Log.info('CryptPad server ready');
        });
    };

    const startCores = () => {
        if (!serverConfig?.private?.nodes_key) {
            if (!serverConfig?.private) {
                serverConfig.private = { };
            }
            serverConfig.private.nodes_key = Crypto.randomBytes(32).toString('base64');
        }
        const corePromises = infraConfig?.core.map((data, index) => {
            // hosted on another machine?
            if (serverId && data.serverId !== serverId) { return; }
            return startNode('core', index, true);
        });

        return Promise.all(corePromises.filter(Boolean))
          .then(() => coresReady());
    };


    // Start process
    if (cliArgs.type) {
        const type = cliArgs.type;
        const index = Number(cliArgs.index || 0);
        if (!serverConfig?.private?.nodes_key) {
            throw Error('E_MISSINGKEY');
        }
        return startNode(type, index, false).catch((err) => {
            if (err) { return Log.error('START_NODE_ERROR', err); }
        });
    } else {
        serverId = cliArgs.server;
        return startCores();
    }
};

if (require.main === module) {
    const { config, infra } = require('./common/load-config')();
    start(config, infra).catch((e) => { console.error('CryptPad server start failed:', e); });
} else {
    module.exports = { start };
}
