// SPDX-FileCopyrightText: 2026 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const Util = require("../common/common-util");
const Crypto = require("../common/crypto.js")('sodiumnative');

const COMMANDS = {};
//let Env = {};

const init = (config, cb) => {
    cb();
};

let onValidateMessage = (msg, vk, cb) => {
    let signedMsg;
    try {
        signedMsg = Crypto.decodeBase64(msg);
    } catch {
        return void cb('E_BAD_MESSAGE');
    }

    let validateKey;
    try {
        validateKey = Crypto.decodeBase64(vk);
    } catch {
        return void cb('E_BADKEY');
    }

    const validated = Crypto.sigVerify(signedMsg, validateKey);
    if (!validated) {
        return void cb('FAILED');
    }
    cb();
};
const onValidateRpc = (signedMsg, signature, publicKey) => {
    if (!(signedMsg && publicKey)) {
        throw new Error("INVALID_ARGS");
    }

    let signedBuffer;
    let pubBuffer;
    let signatureBuffer;

    try {
        signedBuffer = Util.decodeUTF8(signedMsg);
    } catch (e) {
        throw new Error("INVALID_SIGNED_BUFFER");
    }

    try {
        pubBuffer = Util.decodeBase64(publicKey);
    } catch (e) {
        throw new Error("INVALID_PUBLIC_KEY");
    }

    try {
        signatureBuffer = Util.decodeBase64(signature);
    } catch (e) {
        throw new Error("INVALID_SIGNATURE");
    }

    if (pubBuffer.length !== 32) {
        throw new Error("INVALID_PUBLIC_KEY_LENGTH");
    }

    if (signatureBuffer.length !== 64) {
        throw new Error("INVALID_SIGNATURE_LENGTH");
    }

    if (Crypto.detachedVerify(signedBuffer, signatureBuffer, pubBuffer) !== true) {
        throw new Error("FAILED");
    }
};


COMMANDS.VALIDATE_MESSAGE = (data, cb) => {
    onValidateMessage(data.signedMsg, data.validateKey, cb);
};
COMMANDS.VALIDATE_RPC = (data, cb) => {
    try {
        onValidateRpc(data.msg, data.sig, data.key);
    } catch (err) {
        return void cb(err && err.message);
    }
    cb();
};




let ready = false;
process.on('message', function(obj) {
    if (!obj || !obj.txid || !obj.pid) {
        return void process.send({
            error: 'E_INVAL',
            data: obj,
        });
    }

    const command = COMMANDS[obj.command];
    const data = obj.data;

    const cb = function(err, value) {
        process.send({
            error: Util.serializeError(err),
            txid: obj.txid,
            pid: obj.pid,
            value: value,
        }, (e) => {
          if (e) { console.error('E_RESPONSE', Util.serializeError(e)); }
        });
    };

    if (!ready) {
        /*
        if (obj.env) {
            Env = Util.tryParse(obj.env);
        }
        */
        return void init(obj.config, function(err) {
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

// Clean exit
process.on('disconnect', () => { process.exit(0); });

process.on('uncaughtException', function(err) {
    console.error('[%s] UNCAUGHT EXCEPTION IN CORE WORKER', new Date());
    console.error(err);
    console.error("TERMINATING");
    process.exit(1);
});
