// SPDX-FileCopyrightText: 2026 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const Path = require('node:path');
const Express = require('express');
const nThen = require("nthen");
const Core = require("../common/core");
const BlockStore = require("./storage/block");
const Blob = require("./storage/blob.js");
const { setHeaders } = require('../http-server/headers.js');
const CpCrypto = require("../common/crypto.js")('sodiumnative');
const Util = require('../common/common-util');
const MFA = require("./storage/mfa");
const Sessions = require("./storage/sessions");
const Fs = require('node:fs');
const Environment = require('../common/env');
const Logger = require('../common/logger');
const Http = require('node:http');

// Env.modules
const File = require("./storage/file.js");
const Basic = require("./storage/basic.js");
const Pinning = require('./commands/pin.js');
const Decrees = require('./commands/decrees.js');
const Block = require('./commands/block.js');

const COMMANDS = {};
const Env = {
    isWorker: true,
    blobstage: {} // Store file streams to write blobs
};

const onEnvReady = Util.mkEvent(true);

COMMANDS.NEW_DECREES = (data, cb) => {
    const { decrees, type } = data;
    Env.getDecree(type).loadRemote(Env, decrees);
    onEnvReady.fire();
    cb();
};
COMMANDS.CANCEL_UPLOAD = (data, cb) => {
    const { safeKey, size } = data;
    Env.blobStore.cancel(safeKey, size, cb, true);
};
COMMANDS.CLOSE_BLOBSTAGE = (data, cb) => {
    const { safeKey } = data;
    Env.blobStore.closeBlobstage(safeKey);
    cb();
};
COMMANDS.UPDATE_LOGO = (data, cb) => {
    Env.apiLogoCache = undefined;
    cb();
};

const response = Util.response((errLabel, info) => {
    Env.Log.error('WORKER__' + errLabel, info);
});

const initServerHandlers = (Env, app) => {
    app.use(Express.urlencoded({
        extended: true
    }));

    app.use('/blob', function (req, res, next) {
        // Head requests are used to check the size of a blob.
        const url = req.url;
        if (typeof(url) === "string" && Env.blobStore) {
            const s = url.split('/');
            if (s[1] && s[1].length === 2 && s[2] && s[2].length === Env.blobStore.BLOB_LENGTH) {
                Env.blobStore.updateActivity(s[2], () => {});
            }
        }
        if (req.method === 'HEAD') {
            Express.static(Path.resolve(Env.paths.blob), {
                setHeaders: function (res /*, path, stat */) {
                    res.set('Access-Control-Allow-Origin', Env.enableEmbedding? '*': Env.permittedEmbedders);
                    res.set('Access-Control-Allow-Headers', 'Content-Length');
                    res.set('Access-Control-Expose-Headers', 'Content-Length');
                }
            })(req, res, next);
            return;
        }
        next();
    });

    app.use(function (req, res, next) {
    /*  These are pre-flight requests, through which the client
        confirms with the server that it is permitted to make the
        actual requests which will follow */
        if (req.method === 'OPTIONS' && /\/blob\//.test(req.url)) {
            res.setHeader('Access-Control-Allow-Origin', Env.enableEmbedding? '*': Env.permittedEmbedders);
            res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Content-Range,Range,Access-Control-Allow-Origin');
            res.setHeader('Access-Control-Max-Age', 1728000);
            res.setHeader('Content-Type', 'application/octet-stream; charset=utf-8');
            res.setHeader('Content-Length', 0);
            res.statusCode = 204;
            return void res.end();
        }

        setHeaders(Env, req, res);
        if (/[\?\&]ver=[^\/]+$/.test(req.url)) { res.setHeader("Cache-Control", "max-age=31536000"); }
        else { res.setHeader("Cache-Control", "no-cache"); }
        next();
    });

    app.use("/blob", Express.static(Path.resolve(Env.paths.blob), {
        maxAge: Env.DEV_MODE? "0d": "365d"
    }));
    app.use("/datastore",
        (req, res, next) => {
            if (req.method === 'HEAD') {
                next();
            } else {
                res.status(403).end();
            }
        },
        Express.static(Env.paths.channel, {
            maxAge: "0d"
        }
    ));

    Env.plugins.addHttpEndpoints(Env, app, 'storage');

    app.use('/block/', function (req, res, next) {
        const parsed = Path.parse(req.url);
        const name = parsed.name;
        // block access control only applies to files
        // identified by base64-encoded public keys
        // skip everything else, ie. /block/placeholder.txt
        if (/^placeholder\.txt(\?.+)?/.test(parsed.base)) {
            return void next();
        }
        if (typeof(name) !== 'string' || name.length !== 44) {
            return void res.status(404).json({
                error: "INVALID_ID",
            });
        }

        const authorization = req.headers.authorization;

        let mfa_params, sso_params;
        nThen((w) => {
            // First, check whether the block id in question has any MFA settings stored
            MFA.read(Env, name, w((err, content) => {
                // ENOENT means there are no settings configured
                // it could be a 404 or an existing block without MFA protection
                // in either case you can abort and fall through
                // allowing the static webserver to handle either case
                if (err && err.code === 'ENOENT') {
                    return;
                }

                // we're not expecting other errors. the sensible thing is to fail
                // closed - meaning assume some protection is in place but that
                // the settings couldn't be loaded for some reason. block access
                // to the resource, logging for the admin and responding to the client
                // with a vague error code
                if (err) {
                    Env.Log.error('GET_BLOCK_METADATA', err);
                    return void res.status(500).json({
                        code: 500,
                        error: "UNEXPECTED_ERROR",
                    });
                }

                // Otherwise, some settings were loaded correctly.
                // We're expecting stringified JSON, so try to parse it.
                // Log and respond with an error again if this fails.
                // If it parses successfully then fall through to the next block.
                try {
                    mfa_params = JSON.parse(content);
                } catch (err2) {
                    w.abort();
                    Env.Log.error("INVALID_BLOCK_METADATA", err2);
                    return res.status(500).json({
                        code: 500,
                        error: "UNEXPECTED_ERROR",
                    });
                }
            }));

            // Same for SSO settings
            const SSOUtils = Env?.plugins?.SSO?.utils;
            if (!SSOUtils) { return; }
            SSOUtils.readBlock(Env, name, w((err, content) => {
                if (err && (err.code === 'ENOENT' || err === 'ENOENT')) {
                    return;
                }
                if (err) {
                    Env.Log.error('GET_BLOCK_METADATA', err);
                    return void res.status(500).json({
                        code: 500,
                        error: "UNEXPECTED_ERROR",
                    });
                }
                sso_params = content;
            }));
        }).nThen((w) => {
            if (!mfa_params && !sso_params) {
                w.abort();
                next();
            }
        }).nThen((w) => {
            // Block is protected with 2FA or SSO, make sure it still exists
            const url = req.url;
            if (typeof(url) !== "string") { return; }
            const s = url.split('/');
            const id = s[2];
            if (!(s[1]?.length === 2 && BlockStore.isValidKey(id))) { return; }
            BlockStore.isAvailable(Env, id, w((err, val) => {
                if (err) { return; }
                if (val !== false) { return; }
                // Block doesn't exist, send the placeholder
                w.abort();
                return BlockStore.readPlaceholder(Env, id, reason => {
                    res.status(404).json({
                        reason,
                        code: 404
                    });
                });
            }));
        }).nThen((w) => {
            // We should only be able to reach this logic
            // if we successfully loaded and parsed some JSON
            // representing the user's MFA and/or SSO settings.

            // Failures at this point relate to insufficient or incorrect authorization.
            // This function standardizes how we reject such requests.

            // So far the only additional factor which is supported is TOTP.
            // We specify what the method is to allow for future alternatives
            // and inform the client so they can determine how to respond
            // "401" means "Unauthorized"
            const no = () => {
                w.abort();
                res.status(401).json({
                    sso: Boolean(sso_params),
                    method: mfa_params && mfa_params.method,
                    code: 401
                });
            };

            // if you are here it is because this block is protected by MFA or SSO.
            // they will need to provide a JSON Web Token, so we can reject them outright
            // if one is not present in their authorization header
            if (!authorization) { return void no(); }

            // The authorization header should be of the form
            // "Authorization: Bearer <SessionId>"
            // We can reject the request if it is malformed.
            let token = authorization.replace(/^Bearer\s+/, '').trim();
            if (!token) { return void no(); }

            Sessions.read(Env, name, token, (err, contentStr) => {
                if (err) {
                    Env.Log.error('SESSION_READ_ERROR', err);
                    return res.status(401).json({
                        sso: Boolean(sso_params),
                        method: mfa_params && mfa_params.method,
                        code: 401,
                    });
                }

                let content = Util.tryParse(contentStr);

                if (mfa_params && !content.mfa) { return void no(); }
                if (sso_params && !content.sso) { return void no(); }

                if (content.mfa && content.mfa.exp && (+new Date()) > content.mfa.exp) {
                    Env.Log.error("OTP_SESSION_EXPIRED", content.mfa);
                    Sessions.delete(Env, name, token, (err) => {
                        if (err) {
                            Env.Log.error('SESSION_DELETE_EXPIRED_ERROR', err);
                            return;
                        }
                        Env.Log.info('SESSION_DELETE_EXPIRED', err);
                    });
                    return void no();
                }


                if (content.sso && content.sso.exp && (+new Date()) > content.sso.exp) {
                    Env.Log.error("SSO_SESSION_EXPIRED", content.sso);
                    Sessions.delete(Env, name, token, (err) => {
                        if (err) {
                            Env.Log.error('SSO_SESSION_DELETE_EXPIRED_ERROR', err);
                            return;
                        }
                        Env.Log.info('SSO_SESSION_DELETE_EXPIRED', err);
                    });
                    return void no();
                }

                // Interpret the existence of a file in that location as the continued
                // validity of the session. Fall through and let the built-in webserver
                // handle the 404 or serving the file.
                next();
            });
        });
    });

    // TODO this would be a good place to update a block's atime
    // in a manner independent of the filesystem. ie. for detecting and archiving
    // inactive accounts in a way that will not be invalidated by other forms of access
    // like filesystem backups.
    app.use("/block", Express.static(Path.resolve(Env.paths.block), {
        maxAge: "0d",
    }));
    // In case of a 404 for the block, check if a placeholder exists
    // and provide the result if that's the case
    app.use("/block", (req, res, next) => {
        const url = req.url;
        if (typeof(url) === "string") {
            const s = url.split('/');
            if (s[1] && s[1].length === 2 && BlockStore.isValidKey(s[2])) {
                return BlockStore.readPlaceholder(Env, s[2], (content) => {
                    res.status(404).json({
                        reason: content,
                        code: 404
                    });
                });
            }
        }
        next();
    });

    app.use('/upload-blob', Express.json({limit:"500kb"}), (req, res) => {
        if (req.method === 'OPTIONS') {
            res.setHeader('Access-Control-Allow-Origin', Env.enableEmbedding? '*': Env.permittedEmbedders);
            res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Content-Range,Range,Access-Control-Allow-Origin');
            res.setHeader('Access-Control-Max-Age', 1728000);
            res.setHeader('Content-Type', 'application/octet-stream; charset=utf-8');
            res.setHeader('Content-Length', 0);
            res.statusCode = 204;
            return void res.end();
        }

        const { chunk, sig, edPublic } = req.body || {};

        const forbidden = reason => {
            return void res.status(403).send({error: reason});
        };

        try {
            // Check signature
            const sigu8 = Util.decodeBase64(sig);
            const vkey = Util.decodeBase64(edPublic);
            const ok = CpCrypto.sigVerify(sigu8, vkey);
            if (!ok) { return forbidden('INVALID_KEY'); }
            const cookie = Util.encodeUTF8(sigu8.subarray(64));
            // Check cookie
            const safeKey = Util.escapeKeyCharacters(edPublic);
            Env.blobStore.checkUploadCookie(safeKey, value => {
                if (value !== cookie) {
                    return forbidden('INVALID_COOKIE');
                }
                // Upload chunk
                Env.blobStore.upload(safeKey, chunk, (err) => {
                    if (err) {
                        return res.status(500).send({error: err});
                    }
                    // Get new cookie
                    Env.blobStore.uploadCookie(safeKey, (err, _c) => {
                        if (err) {
                            return res.status(500).send({error: err});
                        }
                        res.status(200).send({
                            cookie: _c
                        });
                    });
                });
            });

        } catch (e) {
            return void res.status(500).send({error: e.message});
        }
    });

    app.use('/api/logo', (req, res) => {
        if (Env.apiLogoCache) {
            return res.sendFile(Env.apiLogoCache);
        }
        const path = Env.paths.logo;
        Fs.readdir(path, (err, files) => {
            (files || []).some(file => {
                if (!/^logo\./.test(file)) { return; }
                Env.apiLogoCache = Path.resolve(Path.join(path, file));
                res.sendFile(Env.apiLogoCache);
                return true;
            });
        });
    });
};

const guid = () => {
    let id = Util.uid();
    return response.expected(id)? guid(): id;
};
Env.sendCommand = (cmd, data, cb) => {
    cb ||= () => {};
    const txid = guid();
    response.expect(txid, (err, response) => {
        cb(err, response);
    }, 2*60000); // 2min timeout
    process.send({
        txid, cmd, data,
        pid: Env.pid
    });
};
Env.updateLimits = () => {
    Env.sendCommand('UPDATE_LIMITS', {});
};

// Env.interface
const onInterfaceCmd = (type) => {
    return (id, cmd, data, cb, exclude) => {
        cb ||= () => {};
        Env.sendCommand('STORAGE_INTERFACE', {
            type, id, cmd, data, exclude
        }, cb);
    };
};
Env.interface = {
    'sendQuery': onInterfaceCmd('sendQuery'),
    'sendEvent': onInterfaceCmd('sendEvent'),
    'broadcast': onInterfaceCmd('broadcast'),
};


const init = (config, cb) => {
    Environment.init(Env, config, {
        Block, Pinning, Decrees, CpCrypto,
        BlockStore, Blob, File, Sessions, Basic
    });
    Env.Log = Logger(config.config, Env.myId);

    const {
        archivePath, blobPath, blobStagingPath
    } = Core.getPaths(config);

    nThen(waitFor => {
        // Load blobStore
        Blob.create({
            blobPath,
            blobStagingPath,
            archivePath,
            getSession: safeKey => {
                return Core.getSession(Env.blobstage, safeKey);
            },
            sendCommand: Env.sendCommand
        }, waitFor((err, store) => {
            if (err) {
                waitFor.abort();
                return void cb(err);
            }
            Env.blobStore = store;
        }));
        setInterval(() => {
            Core.expireSessions(Env.blobstage);
        }, Core.SESSION_EXPIRATION_TIME);
    }).nThen(() => {
        // Init http server
        onEnvReady.reg(() => {
            const cfg = config?.infra?.storage[config.index];
            const app = Express();
            const server = Http.createServer(app);
            server.listen(cfg.port, cfg.host, () => {
                Env.Log.debug('HTTP worker listening on port', cfg.port);
            });

            initServerHandlers(Env, app);
        });
        cb();
    });
};

let ready = false;
process.on('message', function(obj) {
    if (!obj || !obj.txid || !obj.pid) {
        return void process.send({
            error: 'E_INVAL',
            data: obj,
        });
    }

    if (response.expected(obj.txid) && (obj.response || obj.error)) {
        response.handle(obj.txid, [obj.error, obj.response]);
        return;
    }

    const command = COMMANDS[obj.command];
    const data = obj.data;
    Env.pid = obj.pid;

    const cb = function(err, value) {
        process.send({
            error: Util.serializeError(err),
            txid: obj.txid,
            pid: obj.pid,
            value: value,
        });
    };

    if (!ready) {
        return void init(obj.config, (err) => {
            if (err) { return void cb(Util.serializeError(err)); }
            ready = true;
            cb();
        });
    }

    if (typeof (command) !== 'function') {
        return void cb("E_BAD_COMMAND");
    }
    command(data, cb);
});
process.on('uncaughtException', function(err) {
    console.error('[%s] UNCAUGHT EXCEPTION IN DB CLUSTER', new Date());
    console.error(err);
    console.error("TERMINATING");
    process.exit(1);
});
