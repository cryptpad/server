// SPDX-FileCopyrightText: 2023 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const Core = module.exports;
const Util = require("./common-util");
const Constants = require("./constants");
const escapeKeyCharacters = Util.escapeKeyCharacters;
// const Path = require('node:path');
const Crypto = require('node:crypto');
const Keys = require("./keys");
//const { fork } = require('child_process');

Core.DEFAULT_LIMIT = 50 * 1024 * 1024;
Core.SESSION_EXPIRATION_TIME = 60 * 1000;

Core.isValidId = (chan) => {
    return chan && chan.length && /^[a-zA-Z0-9=+-]*$/.test(chan) && [
        Constants.STANDARD_CHANNEL_LENGTH,
        Constants.ADMIN_CHANNEL_LENGTH,
        Constants.EPHEMERAL_CHANNEL_LENGTH,
        Constants.BLOB_ID_LENGTH
    ].indexOf(chan.length) > -1;
};

Core.isValidPublicKey = (owner) => {
    return typeof(owner) === 'string' && owner.length === 44;
};

Core.isValidBlockId = id => {
    return typeof(id) === "string" && id.length === 44;
};

const makeToken = Core.makeToken = () => {
    return Number(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER))
        .toString(16);
};

Core.makeCookie = function (token) {
    let time = (+new Date());
    time -= time % 5000;

    return [
        time,
        process.pid,
        token
    ];
};

const parseCookie = (cookie) => {
    if (!(cookie && cookie.split)) { return null; }

    let parts = cookie.split('|');
    if (parts.length !== 3) { return null; }

    let c = {};
    c.time = new Date(parts[0]);
    c.pid = Number(parts[1]);
    c.seq = parts[2];
    return c;
};

Core.getSession = (Sessions, key) => {
    let safeKey = escapeKeyCharacters(key);
    if (Sessions[safeKey]) {
        Sessions[safeKey].atime = +new Date();
        return Sessions[safeKey];
    }
    let user = Sessions[safeKey] = {};
    user.atime = +new Date();
    user.tokens = [
        makeToken()
    ];
    return user;
};

Core.expireSession = (Sessions, safeKey) => {
    let session = Sessions[safeKey];
    if (!session) { return; }
    if (session.blobstage) {
        session.blobstage.close();
    }
    delete Sessions[safeKey];
};

Core.expireSessionAsync = (Env, safeKey, cb) => {
    setTimeout(() => {
        Core.expireSession(Env.Sessions, safeKey);
        cb(void 0, 'OK');
    });
};

const isTooOld = (time, now) => {
    return (now - time) > 300000;
};

Core.expireSessions = (Sessions) => {
    let now = +new Date();
    Object.keys(Sessions).forEach((safeKey) => {
        let session = Sessions[safeKey];
        if (session && isTooOld(session.atime, now)) {
            Core.expireSession(Sessions, safeKey);
        }
    });
};

const addTokenForKey = (Sessions, publicKey, token) => {
    if (!Sessions[publicKey]) { throw new Error('undefined user'); }

    let user = Core.getSession(Sessions, publicKey);
    user.tokens.push(token);
    user.atime = +new Date();
    if (user.tokens.length > 2) { user.tokens.shift(); }
};

Core.isValidCookie = (Sessions, publicKey, cookie) => {
    let parsed = parseCookie(cookie);
    if (!parsed) { return false; }

    let now = +new Date();

    if (!parsed.time) { return false; }
    if (isTooOld(parsed.time, now)) {
        return false;
    }

    // different process. try harder
    if (process.pid !== parsed.pid) {
        return false;
    }

    let user = Core.getSession(Sessions, publicKey);
    if (!user) { return false; }

    let idx = user.tokens.indexOf(parsed.seq);
    if (idx === -1) { return false; }

    if (idx > 0) {
        // make a new token
        // NOTE: this shouldn't happen, idx should always be 0
        addTokenForKey(Sessions, publicKey, Core.makeToken());
    }

    return true;
};

// E_NO_OWNERS
Core.hasOwners = function (metadata) {
    return Boolean(metadata && Array.isArray(metadata.owners));
};

Core.hasPendingOwners = function (metadata) {
    return Boolean(metadata && Array.isArray(metadata.pending_owners));
};

// INSUFFICIENT_PERMISSIONS
Core.isOwner = function (metadata, unsafeKey) {
    return metadata.owners.indexOf(unsafeKey) !== -1;
};

Core.isPendingOwner = function (metadata, unsafeKey) {
    return metadata.pending_owners.indexOf(unsafeKey) !== -1;
};

Core.haveACookie = function (Env, safeKey, cb) {
    cb();
};

Core.getPaths = (mainConfig, isEnv) => {
    const { config } = mainConfig;
    // const { index, config } = mainConfig;
    // const paths = Constants.paths; // XXX use config

    // const idx = String(index);
    /*
    const all = {
        basePath: config.basePath || Path.join(paths.base, idx),
        filePath: config.filePath || Path.join(paths.base, idx, paths.channel),
        blobPath: config.blobPath || Path.join(paths.base, idx, paths.blob),
        blobStagingPath: config.blobStagingPath || Path.join(paths.base, idx, paths.blobstage),
        blockPath: config.blockPath || Path.join(paths.base, idx, paths.block),
        pinPath: config.pinPath || Path.join(paths.base, idx, paths.pin),
        archivePath: config.archivePath || Path.join(paths.base, idx, paths.archive),
        taskPath: config.taskPath || Path.join(paths.base, idx, paths.tasks),
        decreePath: config.decreePath || Path.join(paths.base, "0", paths.decrees),
        logoPath: config.logoPath || Path.join(paths.base, "0", paths.logo),
        challengePath: config.challengePath || Path.join(paths.base, idx, paths.challenges)
    };
    */
    // XXX Compatibility with old server config until migration script is ready
    const all = {
        basePath: config.basePath || config.base || './data',
        filePath: config.filePath || './datastore',
        blobPath: config.blobPath || './blob',
        blobStagingPath: config.blobStagingPath ||'./blobstage',
        blockPath: config.blockPath || './block',
        pinPath: config.pinPath || './pins',
        archivePath: config.archivePath || './data/archive',
        taskPath: config.taskPath || './tasks',
        decreePath: config.decreePath || './data',
        logoPath: config.logoPath || './data/logo',
        challengePath: config.challengePath || './data/challenges',
    };
    if (!isEnv) { return all; }

    // In Env, we use different keys
    return {
        channel: all.filePath,
        data: all.filePath,
        blob: all.blobPath,
        block: all.blockPath,
        staging: all.blobStagingPath,
        pin: all.pinPath,
        decree: all.decreePath,
        logo: all.logoPath,
        base: all.basePath,
        archive: all.archivePath,
        task: all.taskPath
    };

};

Core.getChannelsStorage = (Env, channels) => {
    const channelsByStorage = {};
    channels.forEach(channel => {
        const storageId = Env.getStorageId(channel);
        const list = channelsByStorage[storageId] ||= new Set();
        list.add(channel);
    });
    Object.keys(channelsByStorage).forEach(storageId => {
        channelsByStorage[storageId] = Array.from(channelsByStorage[storageId]);
    });
    return channelsByStorage;
};
Core.getChannelsCore = (Env, channels) => {
    const channelsByCore = {};
    channels.forEach(channel => {
        const coreId = Env.getCoreId(channel);
        const list = channelsByCore[coreId] ||= new Set();
        list.add(channel);
    });
    Object.keys(channelsByCore).forEach(coreId => {
        channelsByCore[coreId] = Array.from(channelsByCore[coreId]);
    });
    return channelsByCore;
};
Core.getUsersFront = (Env, users) => {
    const usersByFront = {};
    users.forEach(userId => {
        const frontId = Env.userCache?.[userId]?.from;
        if (!frontId) { return; }
        const list = usersByFront[frontId] ||= new Set();
        list.add(userId);
    });
    Object.keys(usersByFront).forEach(frontId => {
        usersByFront[frontId] = Array.from(usersByFront[frontId]);
    });
    return usersByFront;
};

const validLimitFields = ['limit', 'plan', 'note', 'users', 'origin'];
Core.isValidLimit = (o) => {
    var valid = o && typeof(o) === 'object' &&
        typeof(o.limit) === 'number' &&
        typeof(o.plan) === 'string' &&
        typeof(o.note) === 'string' &&
        // optionally contains a 'users' array
        (Array.isArray(o.users) || typeof(o.users) === 'undefined') &&
        // check that the object contains only the expected fields
        !Object.keys(o).some(function (k) {
            return validLimitFields.indexOf(k) === -1;
        });

    return valid;
};

Core.applyLimits = (Env) => {
    // DecreedLimits > customLimits > serverLimits;

    // read custom limits from the Environment (taken from config)
    const customLimits = (function (custom) {
        const limits = {};
        Object.keys(custom).forEach(k => {
            const unsafeKey = Keys.canonicalize(k);
            if (!unsafeKey) { return; }
            limits[unsafeKey] = custom[k];
        });
        return limits;
    }(Env.customLimits || {}));

    Env.limits = Env.limits || {};
    Object.keys(customLimits).forEach(k => {
        if (!Core.isValidLimit(customLimits[k])) { return; }
        Env.limits[k] = customLimits[k];
    });
};

Core.coreToStorage = (Env, id, cmd, data, cb) => {
    const storageId = Env.getStorageId(id);
    Env.interface.sendQuery(storageId, cmd, data, res => {
        if (res.error) { return void cb(res.error); }
        cb(void 0, res.data);
    });
};

Core.storageToStorage = (Env, id, cmd, data, cb) => {
    if (id === 'all') {
        Env.interface.broadcast('storage', cmd, data, (errors, data) => {
            if (errors && errors.length) { return void cb(errors, data); }
            cb(void 0, data);
        });
        return;
    }
    const storageId = Env.getStorageId(id);
    Env.interface.sendQuery(storageId, cmd, data, res => {
        if (res.error) { return void cb(res.error); }
        cb(void 0, res.data);
    });
};

Core.storageToFront = (Env, cmd, data, cb) => {
    const id = String(+new Date()); // don't always send to core:0
    const coreId = Env.getCoreId(id);
    Env.interface.sendQuery(coreId, 'STORAGE_FRONT', {
        cmd, data
    }, res => {
        if (res.error) { return void cb(res.error); }
        cb(void 0, res.data);
    });
};

Core.checkStorage = (Env, id, cmd, data, cb) => {
    const storageId = Env.getStorageId(id);
    if (storageId !== Env.myId) {
        Core.storageToStorage(Env, id, cmd, data, cb);
        return false;
    }
    return true;
};

Core.createChannelId = () => {
    return Crypto.randomBytes(16).toString('hex');
};
