// SPDX-FileCopyrightText: 2026 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const Express = require('express');
const Mime = require("mime-types");
const Http = require('node:http');
const Https = require('node:https');
const Path = require('node:path');
const Fs = require('node:fs');

const Logger = require("../common/logger.js");
const Util = require("../common/common-util.js");

const { createProxyServer } = require("httpxy");
const Default = require("./defaults");
const gzipStatic = require('connect-gzip-static');
const Environment = require('../common/env.js');
const { setHeaders } = require('./headers.js');

const COMMANDS = {};
const Env = {
    isWorker: true
};

const onEnvReady = Util.mkEvent(true);

Mime.lookup('wasm');

const initFeedback = (Env, app) => {
    if (!Env.logFeedback) { return; }

    const logFeedback = (url) => {
        url.replace(/\?(.*?)=/, (all, fb) => {
            //Env.Log.feedback(fb, '');
            Env.Log.feedback(['FEEDBACK', fb]);
        });
    };

    app.head(/^\/common\/feedback\.html/, (req, res, next) => {
        logFeedback(req.url);
        next();
    });
};

const getStorageId = (Env, channel) => {
    return Env.getStorageId(channel);
};

const initProxy = (Env, app, infra) => {
    const getURL = obj => {
        if (obj.url) { return obj.url; }
        let url = new URL('http://localhost');
        url.host = obj.host === '::' ? 'localhost' : obj.host;
        url.port = obj.port;
        return url.href;
    };
    const getWs = obj => { // same with ws protocol and /websocket
        if (obj.url) {
            let wsURL = new URL(obj.url);
            wsURL.protocol = wsURL.protocol.replace(/^http/, 'ws');
            return wsURL.href;
        }
        let url = new URL('ws://localhost');
        url.host = obj.host === '::' ? 'localhost' : obj.host;
        url.port = obj.port;
        url.pathname = '/websocket';
        return url.href;
    };

    // "Front" nodes
    const wsList = infra?.front?.map(getWs);
    const httpList = infra?.front?.map(getURL);
    // "Storage" nodes
    const storageList = infra?.storage?.map(getURL);

    let i = 0;
    let j = 0;
    const proxyServer = createProxyServer({});

    const wsProxyUpgrade = (req, socket, head) => {
      proxyServer.ws(req, socket, {
        target: wsList[i++ % wsList.length]
      }, head).catch(e => {
        Env.Log.debug('PROXY_UPGRADE_ERROR', e);
      });
    };

    const httpProxy = (req, res) => {
        proxyServer.web(req, res, {
            target: httpList[j++%httpList.length] + req.baseUrl.slice(1)
        }).catch(e => {
            Env.Log.debug('HTTP_PROXY_ERROR', e);
            res.end();
        });
    };
    const storage0Proxy = (req, res) => {
        proxyServer.web(req, res, {
            target: storageList[0] + req.baseUrl.slice(1)
        }).catch(e => {
            Env.Log.debug('STORE0_PROXY_ERROR', e);
            res.end();
        });
    };

    app.use('/api/updatequota', storage0Proxy);
    app.use('/api/logo', (req, res, next) => {
        setHeaders(Env, req, res);
        if (!Env.customLogo) {
            return res.redirect('/customize/CryptPad_logo_hero.svg');
        }
        storage0Proxy(req, res, next);
    });

    app.use('/extensions.js', httpProxy);
    app.use('/api', httpProxy);

    const checkAllStores = (req, res) => {
        setHeaders(Env, req, res);
        const promiseResponses = storageList.map((baseUrl) => new Promise((res, rej) => {
            const protocol = new URL(baseUrl).protocol;
            if (!['http:', 'https:'].includes(protocol)) {
                return rej();
            }
            const H = protocol === 'http:' ? Http : Https;
            H.get(new URL(req.url, baseUrl), { method: 'HEAD' }, (resp) => {
                const { statusCode } = resp;
                if (statusCode !== 200) {
                    return rej();
                }
                res();
            });
        }));
        Promise.all(promiseResponses)
            .then(() => res.status(200).send('PLACEHOLDER'))
            .catch(() => res.status(404).end());
    };

    app.get('/blob/placeholder.txt', checkAllStores);
    app.get('/block/placeholder.txt', checkAllStores);

    const storeProxy = (req, res) => {
        const split = req.url.split('/');
        const dataId = split[2];
        if (!dataId) { return res.status(520).send(); }
        const id = getStorageId(Env, dataId).slice(8); // remove "storage:"
        proxyServer.web(req, res, {
            target: storageList[id] + req.baseUrl.slice(1)
        }).catch(e => {
            Env.Log.info('STORE_PROXY_ERROR', e);
            res.end();
        });
    };

    app.use('/blob', storeProxy);
    app.use('/datastore', storeProxy);
    app.use('/block', storeProxy);
    app.use('/upload-blob', storeProxy);

    const pluginProxies = Env.plugins.getHttpProxy();
    pluginProxies.forEach(proxyCfg => {
        const proxy = (req, res) => {
            const getTarget = () => {
                if (proxyCfg.target === "storage") {
                    const dataId = proxyCfg.getIdFromReq(req);
                    const id = typeof (dataId) === "number" ? dataId
                        : getStorageId(Env, dataId).slice(8);
                    return storageList[id] + req.baseUrl.slice(1);
                }
                if (proxyCfg.target === "http") {
                    return httpList[j++ % httpList.length]
                        + req.baseUrl.slice(1);
                }
            };
            proxyServer.web(req, res, { target: getTarget() })
            .catch(e => {
              Env.Log.info('PROXY_PLUGIN_ERROR', e);
              res.end();
            });
        };
        app.use(proxyCfg.url, proxy);
    });

    return wsProxyUpgrade;
};

const initHeaders = (Env, app) => {
    app.use((req, res, next) => {
        setHeaders(Env, req, res);
        if (/[\?\&]ver=[^\/]+$/.test(req.url)) {
            res.setHeader("Cache-Control", "max-age=31536000");
        } else {
            res.setHeader("Cache-Control", "no-cache");
        }
        next();
    });
};

const initPlugins = (Env, app) => {
    Env.plugins.addHttpEndpoints(Env, app, 'http');
};

const initStatic = (Env, app) => {
    // serve custom app content from the customize directory
    // useful for testing pages customized with opengraph data
    const root = Env.clientRoot;

    const checkPath = Path.resolve(root, './www');
    if (!Fs.existsSync(checkPath)) { return; }

    app.use(Express.static(Path.resolve(root, './customize/www')));
    app.use(gzipStatic(Path.resolve(root, './www')));

    app.use("/common", Express.static(Path.resolve(root, './src/common')));

    let mainPages = Env.mainPages || Default.mainPages();
    let mainPagePattern = new RegExp('^\/(' + mainPages.join('|') + ').html$');
    app.get(mainPagePattern, Express.static(Path.resolve(root, './customize')));
    app.get(mainPagePattern, Express.static(Path.resolve(root, './customize.dist')));

    const customize = Path.resolve(root, 'customize');
    const customizeDist = Path.resolve(root, 'customize.dist');

    app.use("/customize", Express.static(customize));
    app.use("/customize", Express.static(customizeDist));
    app.use("/customize.dist", Express.static(customizeDist));
    app.use(/^\/[^\/]*$/, Express.static(customize));
    app.use(/^\/[^\/]*$/, Express.static(customizeDist));

    let four04 = Path.resolve(root, './customize.dist/404.html');
    let fivehundred = Path.resolve(root, './customize.dist/500.html');
    let custom_four04 = Path.resolve(root, './customize/404.html');
    let custom_fivehundred = Path.resolve(root, './customize/500.html');

    const send404 = (res, path) => {
        if (!path && path !== four04) { path = four04; }
        Fs.exists(path, (exists) => {
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            if (exists) { return Fs.createReadStream(path).pipe(res); }
            send404(res);
        });
    };
    const send500 = (res, path) => {
        if (!path && path !== fivehundred) { path = fivehundred; }
        Fs.exists(path, (exists) => {
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            if (exists) { return Fs.createReadStream(path).pipe(res); }
            send500(res);
        });
    };
    app.use((req, res) => {

        if (/^(\/favicon\.ico\/|.*\.js\.map|.*\/translations\/.*\.json)/.test(req.url)) {
            // ignore common 404s
        } else {
            Env.Log.info('HTTP_404', req.url);
        }

        res.status(404);
        send404(res, custom_four04);
    });

    // default message for thrown errors in ExpressJS routes
    app.use((err, req, res) => {
        Env.Log.error('EXPRESSJS_ROUTING', {
            error: err.stack || err,
        });
        res.status(500);
        send500(res, custom_fivehundred);
    });
};

COMMANDS.NEW_DECREES = (data, cb) => {
    const { decrees, type } = data;
    Env.getDecree(type).loadRemote(Env, decrees);
    onEnvReady.fire();
    cb();
};

const init = (mainConfig, cb) => {
    const { infra } = mainConfig;

    Environment.init(Env, mainConfig);
    Env.Log = Logger(mainConfig.config, Env.myId);

    const app = Express();

    initFeedback(Env, app);
    const wsProxyUpgrade = initProxy(Env, app, infra);
    initHeaders(Env, app);
    initPlugins(Env, app);
    initStatic(Env, app);

    onEnvReady.reg(() => {
        const httpServer = Http.createServer(app);
        httpServer.listen(Env.httpPort, Env.httpAddress, () => {
            if (process.send) { return; }
            Env.Log.info('HTTP server started');
            if (Env.DEV_MODE) {
                Env.Log.info('DEV mode enabled');
            }
        });
        httpServer.on('upgrade', wsProxyUpgrade);

        if (!Env.httpSafePort) { return; }
        const safeServer = Http.createServer(app);
        safeServer.listen(Env.httpSafePort, Env.httpAddress, () => {
            if (process.send) { return; }
            Env.Log.info('HTTP sandbox started');
        });
    });
    cb();
};

let ready = false;
process.on('message', (obj) => {
    if (!obj || !obj.txid || !obj.pid) {
        return void process.send({
            error: 'E_INVAL',
            data: obj,
        });
    }

    const command = COMMANDS[obj.command];
    const data = obj.data;
    Env.pid = obj.pid;

    const cb = (err, value) => {
        process.send({
            error: Util.serializeError(err),
            txid: obj.txid,
            pid: obj.pid,
            value: value,
        }, (e) => {
            if(e) { console.error('E_RESPONSE', Util.serializeError(e)); }
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
    console.error('[%s] UNCAUGHT EXCEPTION IN HTTP WORKER', new Date());
    console.error(err);
    console.error("TERMINATING");
    process.exit(1);
});

