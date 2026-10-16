// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 XWiki CryptPad Team <contact@cryptpad.org> and contributors
const Util = require("./common-util.js");
const Crypto = require("./crypto.js")("sodiumnative");
const NodeCrypto = require("node:crypto");

let findDestFromId = function(ctx, destId) {
    let destPath = destId.split(':');
    return Util.find(ctx.others, destPath);
};

let findIdFromDest = function(ctx, dest) {
    let found = void 0;
    Object.keys(ctx.others).forEach(type => {
        let idx = ctx.others[type].findIndex(function(socket) {
            return socket === dest;
        });
        if (idx !== -1) {
            found = type + ':' + String(idx);
        }
    });
    return found;
};

const onNewConnection = Util.mkEvent();

const newConnection = (ctx, other, txid, type, data, message) => {
    if (type === 'ACCEPT') {
        const coreId = ctx.pendingConnections?.[txid];
        const [acceptName, acceptIndex] = data.split(':');
        if (typeof (coreId) === 'undefined' || !['core','storage'].includes(acceptName) || Number(acceptIndex) !== coreId) {
            return ctx.Log.error('NEW_CONNECTION_ERROR', ctx.myId, ': unknown connection accepted');
        }
        // Connection accepted, add to others and resolve the promise
        ctx.others[acceptName][acceptIndex] = other;
        ctx.pendingPromises?.[data]?.();
        return;
    }
    if (type !== 'IDENTITY') {
        // queue until we're ready
        ctx.queue.push({other, message});
        return;
    }
    const { type: rcvType, idx, challenge: challengeBase64, nonce: nonceBase64 } = data;
    const challenge = new Uint8Array(Crypto.decodeBase64(challengeBase64));
    const nonce = new Uint8Array(Crypto.decodeBase64(nonceBase64));

    // Check for reused challenges
    if (ctx.ChallengesCache[challengeBase64]) {
        other.disconnect();
        return ctx.Log.error('INTERFACE_CHALLENGE_ERROR', "Reused challenge");
    }
    const msg = Crypto.secretboxOpen(challenge, nonce, ctx.nodes_key);
    if (!msg) {
        other.disconnect();
        return ctx.Log.error('INTERFACE_CHALLENGE_ERROR', "Bad challenge answer");
    }
    let [challType, challIndex, challTimestamp] = String(msg).split(':');
    // This requires servers to be time-synchronised to avoid “Challenge in
    // the future” issue.
    let challengeLife = Number(Date.now()) - Number(challTimestamp);
    // FIXME: allow configurable negative challengeLife if machine are not time-sync
    if (challengeLife < -5000 || challengeLife > ctx.ChallengeLifetime ||
        rcvType !== challType || idx !== Number(challIndex)) {
        other.disconnect();
        return ctx.Log.error('INTERFACE_CHALLENGE_ERROR', "Bad challenge answer");
    }

    // Challenge caching once it’s validated
    // TODO: authenticate the answer
    ctx.ChallengesCache[challengeBase64] = true;
    setTimeout(() => { delete ctx.ChallengesCache[challengeBase64]; }, ctx.ChallengeLifetime);
    other.send([txid, 'ACCEPT', ctx.myId]);

    ctx.others[rcvType][idx] = other;
    ctx.pendingPromises?.[`${rcvType}:${idx}`]?.();
    onNewConnection.fire({
        type: rcvType,
        index: idx
    });
    return;
};

let handleMessage = function(ctx, other, message) {
    let response = ctx.response;

    let parsed = Util.tryParse(message);
    if (!parsed) {
        return void ctx.Log.warn("JSON parse error", message);
    }

    // Message format: [txid, type, data, (extra)]
    // type: MESSAGE, IDENTITY, RESPONSE -- PING, ACK (on every single message?)
    const txid = parsed[0];
    const type = parsed[1];
    const data = parsed[2];

    if (type === 'RESPONSE') {
        if (response.expected(txid)) {
            response.handle(txid, data);
        }
        return;
    }

    let fromId = findIdFromDest(ctx, other);
    if (!fromId) {
        return newConnection(ctx, other, txid, type, data, message);
    }

    if (type !== 'MESSAGE') {
        ctx.Log.error('INTERFACE_SENDMESSAGE_ERROR', ctx.myId, "Unexpected message type", type, ', message:', data);
        return;
    }

    const cmd = data.cmd;
    const args = data.args;
    let cmdObj = ctx.commands[cmd];
    if (cmdObj) {
        cmdObj.handler(args, (error, data) => {
            other.send([txid, 'RESPONSE', { error, data }]);
        }, {
            from: fromId
        });
    }
};

let createHandlers = function(ctx, other) {
    other.onMessage(function(message) {
        handleMessage(ctx, other, message);
    });
    other.onDisconnect(function(_code, _reason) {
        ctx.Log.warn(`Interface disconnected: ${other} from ${ctx.myId}. ${_code}, ${_reason}`);
        // XXX FIXME Depending on the type of node, we should be able
        // to reconnect without restarting everything. Crash everything for now
        console.error('WebSocket Disconnected', ctx.myId, findIdFromDest(ctx, other));
        process.exit(1);
    });
};

const onConnected = (ctx, other, coreId) => {
    let uid = Util.guid(ctx.pendingConnections);
    ctx.pendingConnections[uid] = coreId;

    // Identify with challenge
    const nonce = NodeCrypto.randomBytes(24);
    const msg = Crypto.decodeUTF8(`${ctx.myType}:${ctx.myNumber}:${String(Date.now())}`);
    const challenge = Crypto.encodeBase64(Crypto.secretbox(msg, nonce, ctx.nodes_key));
    createHandlers(ctx, other);
    other.send([uid, 'IDENTITY', { type: ctx.myType, idx: ctx.myNumber, nonce: Crypto.encodeBase64(nonce), challenge }]);
};


let guid = function(ctx) {
    let uid = Util.uid();
    return ctx.response.expected(uid) ? guid(ctx) : uid;
};

let communicationManager = function(ctx) {
    let sendEvent = function(destId, command, args) {
        let dest = findDestFromId(ctx, destId);
        if (!dest) {
            ctx.Log.error('INTERFACE_SENDEVENT_ERROR', "Error: dest", destId, "not found in ctx.", ctx.myId);
            return false;
        }

        let txid = guid(ctx);

        // Message format: [txid, type, data, (extra)]
        let msg = [txid, 'MESSAGE', {
            cmd: command,
            args: args
        }];
        dest.send(msg);
        return true;
    };

    let sendQuery = function(destId, command, args, cb) {
        let dest = findDestFromId(ctx, destId);
        if (!dest) {
            ctx.Log.error("INTERFACE_SENDQUERY_ERROR", "Error: dest", destId, "not found in ctx.", ctx.myId);
            cb('EINVALDEST');
            return false;
        }

        let txid = guid(ctx);

        // Message format: [txid, type, data, (extra)]
        let msg = [txid, 'MESSAGE', {
            cmd: command,
            args: args
        }];
        ctx.response.expect(txid, function(data) {
            cb(data);
        });

        dest.send(msg);
        return true;
    };

    let handleCommands = function(COMMANDS) {
        Object.keys(COMMANDS).forEach(cmd => {
            let f = COMMANDS[cmd];
            if (typeof (f) !== 'function') { return; }
            ctx.commands[cmd] = {
                handler: f
            };
        });
    };

    let disconnect = function() {
        Object.keys(ctx.others).forEach(type => {
            ctx.others[type].forEach(_interface => {
                _interface.disconnect();
            });
        });
        // disconnect own server
        if (ctx.self) { ctx.self.disconnect(); }
    };

    const broadcast = (type, command, args, cb, exclude) => {
        const all = ctx.others[type] || {};
        const promises = [];
        Object.keys(all).forEach(idx => {
            const id = `${type}:${idx}`;
            if (Array.isArray(exclude) && exclude.includes(id)) { return; }
            const p = new Promise((resolve) => {
                sendQuery(id, command, args, answer => {
                    if (answer) { answer.id = id; }
                    resolve(answer);
                });
            });
            promises.push(p);
        });
        Promise.all(promises).then(values => {
            const data = (values || []).map(obj => obj.data).filter(Boolean);
            const error = (values || []).map(obj => {
                if (!obj.error) { return; }
                return {
                    id: obj.id,
                    error: obj.error
                };
            }).filter(Boolean);
            cb(error, data);
        });
    };

    return {
        sendEvent, sendQuery,
        handleCommands, disconnect, broadcast,
        onNewConnection: onNewConnection.reg
    };
};

/* This function initializes the different nodes process and connect them to each other */
const init = (config, cb) => {
    cb = Util.once(cb || function () {});

    const ctx = {
        Log: config.Log,
        myId: config.myId,
        others: {
            storage: [],
            core: [],
            http: [],
            front: []
        },
        commands: {},
        queue: [],
        nodes_key: Crypto.decodeBase64(config?.server?.private?.nodes_key),
        pendingConnections : {},
        pendingPromises : {},
        ChallengesCache: {},
        ChallengeLifetime: 30 * 1000 // 30 seconds
    };

    let parsedId = ctx.myId.split(':');
    ctx.myType = parsedId[0];
    ctx.myNumber = Number(parsedId[1]);

    ctx.response = Util.response((error) => {
        ctx.Log.info('Response error:', error);
    });

    const { connector } = config;
    if (!connector) { return cb('E_MISSINGCONNECTOR'); }

    /* Types:
     *  - core: start a server and connect to lower cores
     *  - ws: connect to all cores
     *  - storage: connect to cores and connect to lower storages
     */

    let manager = communicationManager(ctx);
    const promises = [];

    // Connect to a server and wait for the ACCEPT message
    const connectClient = (id) => {
        ctx.Log.verbose(ctx.myId, 'connecting to', id);
        const p = new Promise((resolve, reject) => {
            const t = setTimeout(() => {
                reject();
            }, 30000);
            const accept = () => {
                clearTimeout(t);
                resolve();
            };
            ctx.pendingPromises[id] = accept;
            connector.initClient(ctx, config, id, onConnected, (err) => {
                if (err) { return reject(err); }
            });
        });
        promises.push(p);
    };
    // Wait for a client to be connected and accepted before resolving
    const waitClient = (id) => {
        ctx.Log.verbose(ctx.myId, 'waiting for', id);
        const p = new Promise((resolve, reject) => {
            const t = setTimeout(() => {
                reject();
            }, 30000);
            const accept = () => {
                clearTimeout(t);
                resolve();
            };
            ctx.pendingPromises[id] = accept;
        });
        promises.push(p);
    };

    if (ctx.myType === "core") {
        // Cores: start a server and connect to other cores

        const myConfig = config.infra.core[ctx.myNumber];
        if (!myConfig) {
            ctx.Log.error('INTERFACE_CONFIG_ERROR', "Error: trying to create a non-existing server");
            throw new Error('INVALID_SERVER_ID');
        }

        // Start websocket server
        const servP = new Promise((resolve, reject) => {
            connector.initServer(ctx, myConfig, createHandlers, (err, selfClient) => {
                if (err) { return reject(err); }
                if (!selfClient) { return reject('E_INITWSSERVER'); }
                resolve();
            });
        });
        promises.push(servP);
        // Connect to "lower" cores
        for (let i = 0; i < ctx.myNumber; i++) {
            connectClient(`core:${i}`);
        }
        // And wait for "bigger" cores
        const length = config.infra.core.length;
        for (let i = (ctx.myNumber+1); i < length; i++) {
            waitClient(`core:${i}`);
        }

    } else if (ctx.myType === "storage") {
        // Storages: start a server and connect to other storages and cores
        const myConfig = config.infra.storage[ctx.myNumber];
        if (!myConfig) {
            ctx.Log.error('INTERFACE_CONFIG_ERROR', "Error: trying to create a non-existing server");
            throw new Error('INVALID_SERVER_ID');
        }

        // Start websocket server
        const servP = new Promise((resolve, reject) => {
            connector.initServer(ctx, myConfig, createHandlers, (err, selfClient) => {
                if (err) { return reject(err); }
                if (!selfClient) { return reject('E_INITWSSERVER'); }
                resolve();
            });
        });
        promises.push(servP);
        // Connect to storages
        for (let i = 0; i < ctx.myNumber; i++) {
            connectClient(`storage:${i}`);
        }
        const length = config.infra.storage.length;
        for (let i = (ctx.myNumber+1); i < length; i++) {
            waitClient(`storage:${i}`);
        }
        // Connect to cores
        config?.infra?.core?.forEach((server, id) => {
            connectClient(`core:${id}`);
        });
    } else {
        // front and http connect to cores
        config?.infra?.core?.forEach((server, id) => {
            connectClient(`core:${id}`);
        });
    }

    Promise.all(promises).then(() => {
        // empty queue
        while(ctx.queue.length) {
            let obj =  ctx.queue.shift();
            handleMessage(ctx, obj.other, obj.message);
        }

        return cb();
    }).catch(e => {
        ctx.Log.error('INTERFACE_UNEXPECTED_ERROR', e);
        throw e instanceof Error ? e : new Error(e);
    });

    return manager;
};

module.exports = { init };
