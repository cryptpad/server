// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 XWiki CryptPad Team <contact@cryptpad.org> and contributors
const Crypto = require('node:crypto');
const Path = require('node:path');

const Util = require("./common-util.js");
const Constants = require("../common/constants.js");
const Logger = require("../common/logger.js");
const Core = require("../common/core.js");

const Nacl = require('tweetnacl/nacl-fast');
const nThen = require("nthen");

const HistoryManager = require("./history-manager.js");
const ChannelManager = require("./channel-manager.js");
const HKUtil = require("./hk-util.js");
const MFAManager = require('./mfa-manager.js');

const Environment = require('../common/env.js');

const Interface = require("../common/interface.js");
const WSConnector = require("../common/ws-connector.js");

const BatchRead = require("./batch-read.js");
const WriteQueue = require("../common/write-queue.js");
const WorkerModule = require("../common/worker-module.js");
const Cluster = require("node:cluster");
const File = require("./storage/file.js");
const Blob = require("./storage/blob.js");
const BlockStore = require("./storage/block.js");
const Sessions = require("./storage/sessions.js");
const Basic = require("./storage/basic.js");

const Decrees = require('./commands/decrees.js');
const Upload = require('./commands/upload.js');
const Pinning = require('./commands/pin.js');
const Quota = require('./commands/quota.js');
const Block = require('./commands/block.js');
const Metadata = require('./commands/metadata.js');
const Admin = require('./commands/admin.js');
const Moderators = require('./commands/moderators.js');
const Linked = require('./commands/linked.js');

const {
    TEMPORARY_CHANNEL_LIFETIME,
    ADMIN_CHANNEL_LENGTH,
    STANDARD_CHANNEL_LENGTH,
    hkId
} = Constants;

const Env = {
    id: Util.uid(),
    metadata_cache: {},
    channel_cache: {},
    pin_cache: {},
    cache_checks: {},
    intervals: {},
    queueStorage: WriteQueue(),
    queueValidation: WriteQueue(),
    queueMetadata: WriteQueue(),
    queueDeletes: WriteQueue(),
    batchIndexReads: BatchRead("HK_GET_INDEX"),
    batchMetadata: BatchRead("GET_METADATA"),
    batchUserPins:  BatchRead('LOAD_USER_PINS'),
    batchTotalSize: BatchRead('GET_TOTAL_SIZE'),
    batchRegisteredUsers: BatchRead("GET_REGISTERED_USERS"),
    batchAccountQuery: BatchRead("QUERY_ACCOUNT_SERVER"),
    batchDiskUsage: BatchRead('GET_DISK_USAGE'),
    selfDestructTo: {},
    blobstage: {} // Store file streams to write blobs
};

Env.checkCache = channel => {
    let f = Env.cache_checks[channel] ||= Util.throttle(() => {
        delete Env.cache_checks[channel];
        if (Env.channel_cache[channel]) { return; }
        delete Env.metadata_cache[channel];
    }, 30000);
    f();
};

Env.channelContainsUser = (channel, userId) => {
    const cache = Env.channel_cache[channel];
    // Check if the channel exists in this storage
    if (!cache || !(cache.users instanceof Set)) { return false; }

    // Check if the user is a member of this channel
    return cache.users.has(userId);
};

const onDropChannel = channel => {
    let meta = Env.metadata_cache[channel];
    delete Env.metadata_cache[channel];
    delete Env.channel_cache[channel];

    if (meta && meta.selfdestruct && Env.selfDestructTo) {
        Env.selfDestructTo[channel] = setTimeout(function() {
            Env.CM?.removeChannel(Env, channel);
        }, TEMPORARY_CHANNEL_LIFETIME);
    }
    if (Env.store) {
        Env.store.closeChannel(channel, function() { });
    }

    const coreId = Env.getCoreId(channel);
    Env.interface.sendEvent(coreId, 'DROP_CHANNEL', { channel });
};

Env.onExpiredChannel = channel => {
    const channelData = Env.channel_cache[channel];
    if (!channelData?.users) { return; }
    const users = Array.from(channelData.users);

    const coreId = Env.getCoreId(channel);
    const message = [0, hkId, 'MSG', null, JSON.stringify({
        error: 'EEXPIRED', channel
    })];
    Env.interface.sendEvent(coreId, 'HISTORY_CHANNEL_MESSAGE', {
        users, message
    });
    onDropChannel(channel);
};

// Handlers
const sendMessage = (userId, channel) => {
    return (message, cb) => {
        if (!userId) { return; }
        const coreId = Env.getCoreId(channel);
        const f = typeof(cb) === "function" ?
            Env.interface.sendQuery :
            Env.interface.sendEvent;
        f(coreId, 'HISTORY_MESSAGE', {
            userId, message
        }, () => {
            // No args for cb, this can be a "readMore" call
            // which will fail if we pass arguments
            cb();
        });
    };
};

const getHistoryHandler = f => {
    return (args, cb) => {
        const parsed = args?.parsed;
        const channel = parsed?.[1];
        const send = sendMessage(args?.userId, channel);
        f(Env, args, send, cb);
    };
};

const onChannelMessageHandler = (args, cb) => {
    Env.CM.onChannelMessage(args, cb);
};

// TODO: move to channel-manager
const joinChannelHandler = (args, cb) => {
    let { channel, userId } = args;

    const channelData = Env.channel_cache[channel] ||= {
        users: new Set()
    };

    if (channel.length === ADMIN_CHANNEL_LENGTH) {
        // don't create a userlist for the broadcast channel
        return void cb(void 0, []);
    }

    const onSuccess = () => {
        // If you're allowed to join the channel, add yourself
        // and callback with the old userlist (without you)
        const _users = Array.from(channelData.users);
        channelData.users.add(userId);
        return void cb(void 0, _users);
    };

    if (channel.length !== STANDARD_CHANNEL_LENGTH) {
        // This is probably an ephemeral channel
        // only conventional channels can be restricted
        return void onSuccess();
    }

    HistoryManager.getMetadata(Env, channel, (err, metadata) => {
        if (err) {
            Env.Log.error('HK_METADATA_ERR', {
                channel, error: err,
            });
        }

        if (metadata?.selfdestruct &&
            metadata.selfdestruct !== Env.id) {
            Env.CM.removeChannel(Env, channel);
            return void cb('ESELFDESTRUCT');
        }

        if (Env.selfDestructTo && Env.selfDestructTo[channel]) {
            clearTimeout(Env.selfDestructTo[channel]);
        }

        if (!metadata?.restricted) {
            // the channel doesn't have metadata, or it does and
            // it's not restricted: either way, let them join.
            return void onSuccess();
        }

        // this channel is restricted. verify that the user in
        // question is in the allow list

        const allowed = HKUtil.listAllowedUsers(metadata);


        const check = (authKeys) => {
            if (HKUtil.isUserSessionAllowed(allowed, authKeys)) {
                return void onSuccess();
            }
            // If the channel is restricted, send the history keeper ID
            // so that they can try to authenticate
            allowed.unshift(hkId);
            // otherwise they're not allowed.
            // respond with a special error that includes the list of keys
            // which would be allowed...
            // FIXME RESTRICT bonus points if you hash the keys to limit data
            //       exposure
            cb("ERESTRICTED", allowed);
        };

        const coreRpc = Env.getCoreId(userId);
        Env.interface.sendQuery(coreRpc, 'GET_AUTH_KEYS', {
            userId
        }, res => {
            check(res?.data || {});
        });
    });
};
const leaveChannelHandler = (args, cb) => {
    const { channel, userId } = args;

    const channelData = Env.channel_cache[channel];
    const users = channelData?.users;
    if (!(users instanceof Set)) {
        return void cb('ENOENT');
    }
    if (!users.has(userId)) {
        return void cb('NOT_IN_CHAN');
    }
    users.delete(userId);

    if (!users.size) { onDropChannel(channel); }

    cb(void 0, Array.from(users));
};

const dropUserFromAll = (userId, cb) => {
    const userLists = {};
    Object.keys(Env.channel_cache).forEach(channel => {
        const channelData = Env.channel_cache[channel];
        const users = channelData.users;
        if (!(users instanceof Set)) { return; }
        if (!users.has(userId)) { return; }
        users.delete(userId);
        if (!users.size) {
            onDropChannel(channel);
            return;
        }
        userLists[channel] = Array.from(users);
    });
    cb(void 0, userLists);
};
const dropUserHandler = (args, cb) => {
    let { channels, userId } = args;

    // If we received this command from "checkCache" in core,
    // it means we won't have the channels list from this user
    // and we must check all our channels...
    if (typeof(channels) === "undefined") {
        return dropUserFromAll(userId, cb);
    }

    const userLists = {};
    channels.forEach(channel => {
        const cache = Env.channel_cache[channel];
        // Check if the channel exists in this storage
        if (!cache || !(cache.users instanceof Set)) { return; }

        // Check if the user is a member of this channel
        if (!cache.users.has(userId)) { return; }

        // Remove the user
        cache.users.delete(userId);

        // Clean the channel if no remaining members
        if (!cache.users.size) {
            onDropChannel(channel);
            return;
        }

        userLists[channel] = Array.from(cache.users);
    });
    cb(void 0, userLists);
};

const newDecreeHandler = (args, cb) => { // bcast from core:0
    const { type, decrees, curveKeys } = args;
    Env.getDecree(type).loadRemote(Env, decrees);
    Env.cacheDecrees(type, decrees);
    if (curveKeys) { Env.curveKeys = curveKeys; }
    Env.clusters.broadcast('NEW_DECREES', {
        type, decrees
    }, () => {
        Env.Log.silly('UPDATE_DECREE_STORAGE_CLUSTER');
    });
    Env.workers.broadcast('NEW_DECREES', {
        type, decrees
    }, () => {
        Env.Log.silly('UPDATE_DECREE_STORAGE_WORKER');
    });
    cb();
};

const getChannelListHandler = (args, cb) => {
    Pinning.getChannelList(Env, args.safeKey, channels => {
        cb(void 0, channels);
    }, true);
};

const accountsLimitsHandler = (args, cb) => { // sent from UI
    Env.limits = args.limits;
    Core.applyLimits(Env);
    cb();
};

// Internal cleanup commands

const getActiveChannels = (args, cb) => {
    cb(void 0, {
        myId: Env.myId,
        channels: Object.keys(Env.channel_cache)
    });
};

/* RPC commands */

const adminDecreeHandler = (decree, cb) => { // sent from UI
    Decrees.onNewDecree(Env, decree, '', cb);
};
const getFileSizeHandler = (channel, cb) => {
    Pinning.getFileSize(Env, channel, cb);
};
const getSingleFileSizeHandler = (args, cb) => {
    Env.worker.getFileSize(args.channel, cb, true);
};
const getMultipleFileSizeHandler = (channels, cb) => {
    Pinning.getMultipleFileSize(Env, channels, cb, true);
};
const getDeletedPadsHandler = (channels, cb) => {
    Pinning.getDeletedPads(Env, channels, cb);
};
const getTotalSizeHandler = (args, cb) => {
    Pinning.getTotalSize(Env, args.safeKey, cb, true);
};
const getChannelsTotalSizeHandler = (channels, cb) => {
    Pinning.getChannelsTotalSize(Env, channels, cb, true);
};
Env.getChannelsTotalSize = Pinning.getChannelsTotalSize;

const getRegisteredUsersHandler = (args, cb) => {
    Pinning.getRegisteredUsers(Env, cb, true);
};

const addLinkedDocumentsHandler = (channels, cb) => {
    Pinning.addLinkedDocuments(Env, channels, cb, true);
};
const getMetadataRawHandler = (args, cb) => {
    // don't resolve linked, no redirect
    Metadata.getMetadataRaw(Env, args?.channel, cb, false, true);
};

const setMetadataHandler = (args, cb) => {
    Metadata.setMetadata(Env, args, cb);
};
const getMetadataHandler = (args, cb) => {
    HistoryManager.getMetadata(Env, args?.channel, cb);
};
const isNewChannelHandler = (args, cb) => {
    Env.CM.isNewChannel(Env, args?.channel, cb);
};

const writePrivateMessageHandler = (args, cb) => {
    Env.CM.writePrivateMessage(Env, args, cb);
};
const deleteChannelLineHandler = (args, cb) => {
    Env.CM.deleteMailboxMessage(Env, args, cb);
};

const getPinningResetHandler = (data, cb) => {
    const { channels, safeKey } = data;
    Pinning.resetUserPins(Env, safeKey, channels, cb);
};
const getPinningPinHandler = (data, cb) => {
    const { channels, safeKey } = data;
    Pinning.pinChannel(Env, safeKey, channels, cb);
};
const getPinningUnpinHandler = (data, cb) => {
    const { channels, safeKey } = data;
    Pinning.unpinChannel(Env, safeKey, channels, cb);
};

const getHashHandler = (data, cb) => {
    Pinning.getHash(Env, data.safeKey, cb);
};
const archivePinLogHandler = (data, cb) => {
    Pinning.removePins(Env, data.safeKey, cb);
};
const trimPinLogHandler = (data, cb) => {
    Pinning.trimPins(Env, data.safeKey, cb);
};

const clearOwnedChannelHandler = (data, cb) => {
    Env.CM.clearOwnedChannel(Env, data, cb);
};
const removeOwnedChannelHandler = (data, cb) => {
    Env.CM.removeOwnedChannel(Env, data, cb);
};
const trimHistoryHandler = (data, cb) => {
    Env.CM.trimHistory(Env, data, cb);
};

const blockCheckHandler = (data, cb) => {
    BlockStore.check(Env, data.blockId, cb, true);
};

/* Start of the node */

const callWithEnv = f => {
    return function () {
        [].unshift.call(arguments, Env);
        return f.apply(null, arguments);
    };
};

// List accepted commands
let COMMANDS = {
    'JOIN_CHANNEL': joinChannelHandler,
    'LEAVE_CHANNEL': leaveChannelHandler,
    'GET_HISTORY': getHistoryHandler(HistoryManager.onGetHistory),
    'GET_FULL_HISTORY': getHistoryHandler(HistoryManager.onGetFullHistory),
    'GET_HISTORY_RANGE': getHistoryHandler(HistoryManager.onGetHistoryRange),
    'CHANNEL_MESSAGE': onChannelMessageHandler,
    'DROP_USER': dropUserHandler,
    'NEW_DECREES': newDecreeHandler,

    'ADMIN_DECREE': adminDecreeHandler,
    'ACCOUNTS_LIMITS': accountsLimitsHandler,

    'GET_CHANNEL_LIST': getChannelListHandler,
    'GET_MULTIPLE_FILE_SIZE': getMultipleFileSizeHandler,
    'GET_TOTAL_SIZE': getTotalSizeHandler,
    'GET_CHANNELS_TOTAL_SIZE': getChannelsTotalSizeHandler,
    'GET_REGISTERED_USERS': getRegisteredUsersHandler,

    'ADD_LINKED_DOCUMENTS': addLinkedDocumentsHandler,
    'GET_SINGLE_FILE_SIZE': getSingleFileSizeHandler,
    'GET_LINKED_DOCUMENTS': callWithEnv(Linked.getLinkedDocuments),
    'ADD_LINKED_DOCUMENT': callWithEnv(Linked.addLinkedDocument),
    'RESET_LINKED_DOCUMENTS': callWithEnv(Linked.resetLinkedDocuments),
    'GET_HISTORY_SIZE': callWithEnv(Linked.getHistorySize),

    'GET_METADATA': getMetadataHandler,
    'GET_METADATA_RAW': getMetadataRawHandler,

    'RPC_IS_NEW_CHANNEL': isNewChannelHandler,
    'RPC_WRITE_PRIVATE_MESSAGE': writePrivateMessageHandler,
    'RPC_DELETE_CHANNEL_LINE': deleteChannelLineHandler,
    'RPC_SET_METADATA': setMetadataHandler,

    'RPC_GET_FILE_SIZE': getFileSizeHandler,
    'RPC_GET_DELETED_PADS': getDeletedPadsHandler,
    'RPC_PINNING_RESET': getPinningResetHandler,
    'RPC_PINNING_PIN': getPinningPinHandler,
    'RPC_PINNING_UNPIN': getPinningUnpinHandler,
    'RPC_GET_HASH': getHashHandler,
    'RPC_ARCHIVE_PIN_LOG': archivePinLogHandler,
    'RPC_TRIM_PIN_LOG': trimPinLogHandler,

    'RPC_CLEAR_OWNED_CHANNEL': clearOwnedChannelHandler,
    'RPC_REMOVE_OWNED_CHANNEL': removeOwnedChannelHandler,
    'RPC_TRIM_HISTORY': trimHistoryHandler,

    'HTTP_UPLOAD_COOKIE': callWithEnv(Upload.cookie),
    'RPC_UPLOAD_STATUS': callWithEnv(Upload.status),
    'RPC_UPLOAD_CANCEL': callWithEnv(Upload.cancel),
    'RPC_UPLOAD_CHUNK': callWithEnv(Upload.upload),
    'RPC_UPLOAD_COMPLETE': callWithEnv(Upload.complete),
    'RPC_UPLOAD_COMPLETE_OWNED': callWithEnv(Upload.completeOwned),

    // Block/registration commands
    'HTTP_MFA_CHECK': callWithEnv(MFAManager.checkMFA),
    'HTTP_UPDATE_SESSION': callWithEnv(MFAManager.updateSession),
    'HTTP_WRITE_BLOCK': callWithEnv(Block.writeLoginBlock),
    'HTTP_REMOVE_BLOCK': callWithEnv(Block.removeLoginBlock),

    'TOTP_SETUP': callWithEnv(MFAManager.setupCheck),
    'TOTP_SETUP_COMPLETE': callWithEnv(MFAManager.setupComplete),
    'TOTP_VALIDATE': callWithEnv(MFAManager.validateCheck),
    'TOTP_VALIDATE_COMPLETE': callWithEnv(MFAManager.validateComplete),
    'TOTP_MFA_CHECK': callWithEnv(MFAManager.statusCheck),
    'TOTP_REVOKE': callWithEnv(MFAManager.revokeCheck),
    'TOTP_REVOKE_COMPLETE': callWithEnv(MFAManager.revokeComplete),
    'TOTP_WRITE_BLOCK': callWithEnv(MFAManager.writeCheck),
    'TOTP_WRITE_BLOCK_COMPLETE': callWithEnv(MFAManager.writeComplete),
    'TOTP_REMOVE_BLOCK': callWithEnv(MFAManager.removeCheck),
    'TOTP_REMOVE_BLOCK_COMPLETE': callWithEnv(MFAManager.removeComplete),

    // Block commands from other storages
    'BLOCK_CHECK': blockCheckHandler,
    'BLOCK_GET_MFA': callWithEnv(MFAManager.getMFA),
    'SESSIONS_CMD': callWithEnv(MFAManager.sessionsCmd),
    'USER_REGISTRY_CMD': callWithEnv(MFAManager.userRegistryCmd),
    'INVITATION_CMD': callWithEnv(MFAManager.invitationCmd),

    // Admin commands
    'ADMIN_CMD': callWithEnv(Admin.command),

    // Internal commands
    'GET_ACTIVE_CHANNELS': getActiveChannels
};

const initWorkerCommands = () => {
    Env.worker ||= {};
    Env.worker.computeMetadata = (channel, cb) => {
        Env.store.getWeakLock(channel, _next => {
            let avg = Env.plugins?.MONITORING?.average(`computeMetadata`);
            const next = () => { _next(); avg?.time(); };
            Env.workers.send('COMPUTE_METADATA', {
                channel
            }, Util.both(next, cb));
        });
    };
    Env.worker.computeIndex = (channel, cb) => {
        Env.store.getWeakLock(channel, _next => {
            let avg = Env.plugins?.MONITORING?.average(`computeIndex`);
            const next = () => { _next(); avg?.time(); };
            Env.workers.send('COMPUTE_INDEX', {
                channel
            }, Util.both(next, cb));
        });
    };
    Env.worker.getHashOffset = (channel, hash, cb) => {
        Env.store.getWeakLock(channel, _next => {
            let avg = Env.plugins?.MONITORING?.average(`getHashOffset`);
            const next = () => { _next(); avg?.time(); };
            Env.workers.send('GET_HASH_OFFSET', {
                channel, hash
            }, Util.both(next, cb));
        });
    };
    Env.worker.getOlderHistory = (channel, oldestKnownHash, untilHash, desiredMessages, desiredCheckpoint, cb) => {
        Env.store.getWeakLock(channel, (_next) => {
            let avg = Env.plugins?.MONITORING?.average(`getOlderHistory`);
            const next = () => { _next(); avg?.time(); };
            Env.workers.send('GET_OLDER_HISTORY', {
                channel, oldestKnownHash, untilHash, desiredMessages, desiredCheckpoint
            }, Util.both(next, cb));
        });
    };

    // Pinning
    Env.worker.getMultipleFileSize = (channels, cb) => {
        Env.workers.send("GET_MULTIPLE_FILE_SIZE", {
            channels: channels,
        }, cb, true);
    };
    Env.worker.getTotalSize = (channels, cb) => {
        // we could take out locks for all of these channels,
        // but it's OK if the size is slightly off
        Env.workers.send('GET_TOTAL_SIZE', {
            channels: channels,
        }, cb);
    };
    Env.worker.getPinState = (safeKey, cb) => {
        Env.pinStore.getWeakLock(safeKey, (_next) => {
            let avg = Env.plugins?.MONITORING?.average(`getPinState`);
            const next = () => { _next(); avg?.time(); };
            Env.workers.send('GET_PIN_STATE', {
                key: safeKey
            }, Util.both(next, cb));
        });
    };
    Env.worker.getPinActivity = (safeKey, cb) => {
        Env.pinStore.getWeakLock(safeKey, next => {
            Env.workers.send('GET_PIN_ACTIVITY', {
                key: safeKey
            }, Util.both(next, cb));
        });
    };
    Env.worker.getPinInfo = (safeKey, cb) => {
        Env.pinStore.getWeakLock(safeKey, (_next) => {
            let avg = Env.plugins?.MONITORING?.average(`getPinState`);
            const next = () => { _next(); avg?.time(); };
            Env.workers.send('GET_PIN_INFO', {
                key: safeKey
            }, Util.both(next, cb));
        });
    };

    Env.worker.getDeletedPads = (channels, cb) => {
        let avg = Env.plugins?.MONITORING?.average(`getDeletedPads`);
        const next = Util.both(cb, avg?.time);
        Env.workers.send("GET_DELETED_PADS", {
            channels: channels,
        }, next);
    };
    Env.worker.hashChannelList = (channels, cb) => {
        Env.workers.send('HASH_CHANNEL_LIST', {
            channels: channels,
        }, cb);
    };

    Env.worker.completeUpload = (safeKey, arg, owned, size, linked, expire, cb) => {
        Env.workers.send('COMPLETE_UPLOAD', {
            safeKey, arg, owned, size, linked, expire
        }, cb);
    };

    Env.worker.removeOwnedBlob = (blobId, safeKey, reason, cb) => {
        Env.workers.send('REMOVE_OWNED_BLOB', {
            safeKey, blobId, reason
        }, cb);
    };

    // RPC
    Env.worker.getFileSize = (channel, cb, singleFile) => {
        if (!singleFile) {
            return Linked.getFileSize(Env, { channel }, cb);
        }
        Env.workers.send('GET_FILE_SIZE', {
            channel,
            singleFile // ignore linked documents
        }, cb);
    };

    Env.worker.checkSignature = (msg, sig, key, cb) => {
        Env.workers.send('VALIDATE_DETACHED', {
            msg, sig, key
        }, cb);
    };


    // Tasks
    Env.worker.runTasks = (cb) => {
        // time out after 10 minutes
        Env.workers.send('RUN_TASKS', {}, cb, 1000 * 60 * 10);
    };
    Env.worker.writeTask = (time, command, args, cb) => {
        Env.workers.send('WRITE_TASK', {
            time: time,
            task_command: command,
            args: args,
        }, cb);
    };

    // Admin
    Env.worker.getLastChannelTime = (channel, cb) => {
        Env.workers.send('GET_LAST_CHANNEL_TIME', {
            channel
        }, cb);
    };
    Env.worker.readReport = (args, cb) => {
        Env.workers.send('READ_REPORT', args, cb);
    };
    Env.worker.accountArchivalStart = (args, cb) => {
        Env.workers.send('ACCOUNT_ARCHIVAL_START', args, cb);
    };
    Env.worker.accountRestoreStart = (args, cb) => {
        Env.workers.send('ACCOUNT_RESTORE_START', args, cb);
    };
};

const initAccountsIntervals = () => {
    const pingAccountsDaily = () => {
        Quota.pingAccountsDaily(Env, e => {
            if (e) { Env.Log.warn('dailyPing', e); }
        });
    };
    pingAccountsDaily();
    Env.intervals.dailyPing = setInterval(pingAccountsDaily, 24*3600*1000);

    const updateLimits = () => { Env.updateLimits(); };
    Quota.applyCustomLimits(Env);
    updateLimits();
    if (Env.accounts_api) {
        Env.intervals.quotaUpdate = setInterval(updateLimits, 3600*1000);
    }

};

const initHttpServer = (Env, mainConfig, _cb) => {
    const cb = Util.mkAsync(_cb);

    Cluster.setupPrimary({
        exec: Path.join(__dirname, './storage.cluster.js'),
        args: [],
    });
    const WORKERS = Env.maxWorkers['storage-http'] || 2;
    const workerConfig = {
        Log: Env.Log,
        noTaskLimit: true,
        customFork: () => {
            return Cluster.fork({});
        },
        maxWorkers: WORKERS,
        maxJobs: Env.maxJobs['storage-http'] || 10,
        commandTimers: {}, // time spent on each command
        config: mainConfig,
        Env: { // Serialized Env (Environment.serialize)
        }
    };

    let ready = 0;
    Cluster.on('online', () => {
        ready++;
        if (ready === WORKERS) {
            cb();
        }
    });

    Env.clusters = WorkerModule(workerConfig);
    Env.clusters.onNewWorker(state => {
        Object.keys(Env.allDecrees).forEach(type => {
            const decrees = Env.allDecrees[type];
            Env.clusters.sendTo(state, 'NEW_DECREES', {
                decrees, type
            }, () => {
                Env.Log.silly('UPDATE_DECREE_STORAGE_WORKER');
            });
        });
    });

    Env.clusters.on('STORAGE_INTERFACE', (args, cb) => {
        const { type, id, cmd, data, exclude } = args;
        const f = Env.interface[type];
        if (typeof(f) !== "function") { return void cb('EINVAL'); }
        f(id, cmd, data, cb, exclude);
    });
    Env.clusters.on('UPLOAD_GET_SESSION', (args, cb) => {
        const { safeKey } = args;
        const session = Core.getSession(Env.blobstage, safeKey);
        cb(void 0, {
            currentUploadSize: session.currentUploadSize,
            pendingUploadSize: session.pendingUploadSize
        });
    });
    Env.clusters.on('UPLOAD_REPORT_SESSION', (args, cb) => {
        const { safeKey, len } = args;
        const session = Core.getSession(Env.blobstage, safeKey);
        session.currentUploadSize += len;
        cb();
    });
    Env.clusters.on('UPDATE_LIMITS', (args, cb) => {
        Env.updateLimits();
        cb();
    });
    Env.cluster = {};
    Env.cluster.closeBlobstage = safeKey => {
        Env.clusters.broadcast('CLOSE_BLOBSTAGE', { safeKey }, () => {
            Env.Log.verbose('CLOSE_BLOBSTAGE');
        });
    };
};

const onInitialized = (Env, _cb) => {
    const cb = Util.mkAsync(_cb);

    nThen(waitFor => {
        Env.plugins.call('initStorage')(Env, waitFor);
    }).nThen(() => {
        cb();
    });

};

// Connect to core
const start = (mainConfig) => {
    const { myId, index, infra, config } = mainConfig;

    Environment.init(Env, mainConfig, {
        Block, Pinning, Decrees,
        BlockStore, Blob, File, Sessions, Basic,
        HKUtil
    });

    Env.Log = Logger(config, myId);

    Env.updateLimits = () => {
        if (index !== 0) { return; }
        Quota.updateCachedLimits(Env, (e, limits) => {
            if (!Env.accounts_api) { return; }
            if (e) { return Env.Log.warn('LIMIT_UPDATE', e); }
            if (!limits) { return; }
            Env.interface.broadcast('core', 'ACCOUNTS_LIMITS', {
                limits
            }, () => {});
        });
    };

    const curve = Nacl.box.keyPair();
    let curveKeys = Env.curveKeys = {
        curvePublic: Util.encodeBase64(curve.publicKey),
        curvePrivate: Util.encodeBase64(curve.secretKey)
    };
    Env.sendDecrees = (decrees, type, _cb) => {
        const cb = Util.mkAsync(_cb || function () {});
        const freshKey = String(+new Date());
        Env.cacheDecrees(type, decrees);
        nThen(waitFor => {
            Env.interface.broadcast('core', 'NEW_DECREES', {
                freshKey,
                curveKeys,
                decrees,
                type
            }, waitFor());
            Env.workers.broadcast('NEW_DECREES', {
                decrees, type
            }, waitFor(() => {
                Env.Log.silly('UPDATE_DECREE_STORAGE_WORKER');
            }));
            Env.clusters.broadcast('NEW_DECREES', {
                type, decrees
            }, waitFor(() => {
                Env.Log.silly('UPDATE_DECREE_STORAGE_CLUSTER');
            }));
            curveKeys = undefined;
        }).nThen(() => {
            cb();
        });
    };

    const interfaceConfig = {
        connector: WSConnector,
        index,
        infra,
        server: config,
        myId,
        Log: Env.Log
    };

    const {
        filePath, pinPath, archivePath, blobPath, blobStagingPath
    } = Core.getPaths(mainConfig);
    nThen(waitFor => {
        File.create({
            filePath, archivePath
        }, waitFor((err, store) => {
            if (err) { throw new Error(err); }
            Env.store = store;
        }));
        File.create({
            filePath: pinPath,
            archivePath,
            volumeId: 'pins',
        }, waitFor((err, s) => {
            if (err) { throw err; }
            Env.pinStore = s;
        }));
        Blob.create({
            blobPath,
            blobStagingPath,
            archivePath,
            getSession: safeKey => {
                return Core.getSession(Env.blobstage, safeKey);
            }
        }, waitFor((err, store) => {
            if (err) { throw new Error(err); }
            Env.blobStore = store;
        }));
    }).nThen(() => {
        let tasks_running;
        Env.intervals.taskExpiration = setInterval(() => {
            if (Env.disableIntegratedTasks) { return; }
            if (tasks_running) { return; }
            tasks_running = true;
            Env.worker.runTasks(err => {
                if (err) {
                    Env.Log.error('TASK_RUNNER_ERR', err);
                }
                tasks_running = false;
            });
        }, 1000 * 60 * 5); // run every five minutes

        Env.intervals.pinExpirationInterval = setInterval(() => {
            Core.expireSessions(Env.pin_cache);
        }, Core.SESSION_EXPIRATION_TIME);

        Env.intervals.blobstageExpirationInterval = setInterval(() => {
            // Contains currentUploadSize & pendingUploadSize
            // The file stream is stored in the workers
            Core.expireSessions(Env.blobstage);
        }, Core.SESSION_EXPIRATION_TIME);
    }).nThen((waitFor) => {
        const WORKERS = Env.maxWorkers['storage'] || 2;
        const workerConfig = {
            Log: Env.Log,
            workerPath: './storage.worker.js',
            maxWorkers: WORKERS,
            maxJobs: Env.maxJobs['storage'] || 10,
            commandTimers: {}, // time spent on each command
            config: mainConfig,
            Env: { // Serialized Env (Environment.serialize)
            }
        };
        Env.workers = WorkerModule(workerConfig);
        Env.workers.onNewWorker(state => {
            Object.keys(Env.allDecrees).forEach(type => {
                const decrees = Env.allDecrees[type];
                Env.workers.sendTo(state, 'NEW_DECREES', {
                    decrees, type
                }, () => {
                    Env.Log.silly('UPDATE_DECREE_STORAGE_WORKER');
                });
            });
        });
        initWorkerCommands();

        Env.CM = ChannelManager.create(Env);

        initHttpServer(Env, mainConfig, waitFor());
    }).nThen(waitFor => {
        Env.interface = Interface.init(interfaceConfig, waitFor(err => {
            if (err) {
                console.error(interfaceConfig.myId, ' error:', err);
                return;
            }
        }));

        // List accepted commands
        Env.plugins.call('addStorageCommands')(Env, COMMANDS);
        Env.interface.handleCommands(COMMANDS);
    }).nThen(waitFor => {
        // Only storage:0 can manage decrees, moderators and accounts
        if (index !== 0) { return; }
        initAccountsIntervals();

        Env.moderators = Moderators.getKeysSync(Env).map(safeKey => {
            return Util.unescapeKeyCharacters(safeKey);
        });
        Env.interface.sendQuery('core:0', 'SET_MODERATORS', Env.moderators, waitFor());
    }).nThen(waitFor => {
        // Only storage:0 can manage decrees, moderators and accounts
        if (index !== 0) { return; }

        Env.adminDecrees.load(Env, waitFor((err, toSend) => {
            if (err) {
                waitFor.abort();
                return Env.Log.error('DECREES_LOADING_ERROR', err);
            }

            Env.sendDecrees(toSend, '');
        }));
    }).nThen(waitFor => {
        onInitialized(Env, waitFor());
    }).nThen(waitFor => {
        // BEARER_SECRET decree (storage:0 only)
        if (index !== 0) { return; }
        if (Env.bearerSecret) { return; }

        const bearerSecret = Util.encodeBase64(Crypto.randomBytes(32));
        const decree = [
            'SET_BEARER_SECRET',
            [bearerSecret],
            'INTERNAL',
            +new Date()
        ];
        Decrees.onNewDecree(Env, decree, '', waitFor());
    }).nThen((w) => {
        BlockStore.rootPlaceholderCreate(Env, w((err) => {
            if (err) {
                console.warn(`${myId}: Impossible to create block's placeholder. Please check the value of blockPath in your config.js file and if you have write access on it.`);
            };
        }));
    }).nThen(() => {
        // INSTALL TOKEN admin decree (storage:0 only)
        if (index !== 0) { return; }

        let admins = Env.admins || [];
        // If we don't have any admin on this instance
        // print an onboarding link
        if (Array.isArray(admins) && admins.length) { return; }
        let token = Env.installToken;
        let printLink = () => {
            let url = `${Env.httpUnsafeOrigin}/install/#${token}`;
            console.log('=============================');
            console.log('Create your first admin account and customize your instance by visiting');
            console.log(url);
            console.log('=============================');

        };
        // If we already have a token, print it
        if (token) { return void printLink(); }

        // Otherwise create a new token
        token = Crypto.randomBytes(32).toString('hex');

        let decree = ["ADD_INSTALL_TOKEN",[token],"",+new Date()];
        Decrees.onNewDecree(Env, decree, '', () => {
            printLink();
        });
    }).nThen(() => {
        if (process.send !== undefined) {
            process.send({ type: 'storage', index, msg: 'READY', pid: process.pid });
        } else {
            console.log(myId, 'started');
        }
    });
};

module.exports = {
    start
};
