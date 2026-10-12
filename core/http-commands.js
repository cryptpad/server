// SPDX-FileCopyrightText: 2023 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const Crypto = require('../common/crypto.js')('sodiumnative');
const Util = require('../common/common-util.js');
//const plugins = require("./plugin-manager"); // XXX

const StorageCommands = require("./challenges/storage.js");

const Challenge = require("./storage/challenge.js");
    // C.read(Env, id, cb)
    // C.write(Env,id, data, cb)
    // C.delete(Env, id, cb)

const CHALLENGE_EXPIRY = 60_000;

/*
The API for command definition consists of two stages:

Clients first send a command and its associated parameters.
The server validates that the command is supported, and that
the provided parameters are valid. If it fails validation for any reason,
the server responds with an error and the protocol is aborted.

COMMANDS[COMMAND_NAME] = function (Env, body, cb) {
    // inspect parameters in the request body
    if (!body.essential_parameter) {
        return void cb('NO');
    }
    cb();
};

Commands whose parameters are successfully validated
have those parameters stored on the disk (or a relational DB in the future).
The server then requests that the client sign their well-formulated
command along with a server-generated transaction id ('txid': randomized to prevent replays)
and a date (so that it can ensure that the client responds within a reasonable window.

Clients then respond with a txid and a cryptographic signature
which matches the parameters of the command. The server loads the command
with the corresponding txid, checks that it was signed within a reasonable time window,
validates the signature, and attempts to complete the command's execution:

COMMAND[COMMAND_NAME].complete = function (Env, body, cb) {
    doAThing(function (err, values) {
        if (err) {
            // Log the error and respond that the command was not successful
            return void cb("SORRY_BUT_IM_NOT_OK");
        }
        cb(void 0, {
            arbitrary: values,
        });
    });
};

In this second stage the protocol can be aborted if the client has done something wrong:
(ie. if it did not produce a valid signature for the command)
or it can can fail because the server was not able to complete the requested task
(ie. because of an I/O error or because an error was thrown and caught).

It is intended that the server will respond with an appropriate error if
the request cannot be completed, and it will respond OK if everything completed successfully.

*/

const COMMANDS = {};

// Methods allowing clients to configure Time-based One-Time Passwords for their login-block,
// and to authenticate new sessions once a TOTP secret has been associated with their account,
const NOAUTH = require("./challenges/base.js");

COMMANDS.TEST = NOAUTH.TEST;
COMMANDS.UPLOAD_COOKIE = NOAUTH.UPLOAD_COOKIE;
COMMANDS.MFA_CHECK = NOAUTH.MFA_CHECK;
COMMANDS.WRITE_BLOCK = NOAUTH.WRITE_BLOCK; // Account creation + password change
COMMANDS.REMOVE_BLOCK = NOAUTH.REMOVE_BLOCK;

const TOTP = [
    'TOTP_SETUP',
    'TOTP_VALIDATE',
    'TOTP_MFA_CHECK',
    'TOTP_REVOKE',
    'TOTP_WRITE_BLOCK', // Password change only for now (v5.5.0)
    'TOTP_REMOVE_BLOCK'
];
const TotpCommands = StorageCommands.add(TOTP, ['TOTP_MFA_CHECK']);
TOTP.forEach(id => { COMMANDS[id] = TotpCommands[id]; });

/*
// XXX plugins
// Load challenges added by plugins
Object.keys(plugins || {}).forEach(id => {
    try {
        let plugin = plugins[id];
        if (!plugin.challenge) { return; }
        let commands = plugin.challenge;
        Object.keys(commands).forEach(cmd => {
            if (COMMANDS[cmd]) { return; } // Don't overwrite
            COMMANDS[cmd] = commands[cmd];
        });
    } catch (e) {}
});
*/

let initialized = false;
const initPlugins = Env => {
    if (initialized) { return; }
    initialized = true;

    // Load challenges added by plugins
    const pluginChallenges = Env.plugins.get('challenges');
    pluginChallenges.forEach(challenges => {
        try {
            if (!Array.isArray(challenges)) { return; }
            const commands = StorageCommands.add(challenges);
            Object.keys(commands).forEach(id => {
                COMMANDS[id] = commands[id];
            });
        } catch (e) {}
    });
};

/*
const SSO = plugins.SSO && plugins.SSO.challenge;
COMMANDS.SSO_AUTH = SSO.SSO_AUTH;
COMMANDS.SSO_AUTH_CB = SSO.SSO_AUTH_CB;
COMMANDS.SSO_WRITE_BLOCK = SSO.SSO_WRITE_BLOCK; // Account creation only
COMMANDS.SSO_UPDATE_BLOCK = SSO.SSO_UPDATE_BLOCK; // Password change
COMMANDS.SSO_VALIDATE = SSO.SSO_VALIDATE;
*/

// this function handles the first stage of the protocol
// (the server's validation of the client's request and the generation of its challenge)
const handleCommand = (Env, body, cb) => {
    const command = body.command;

    // reject if the command does not have a corresponding function
    if (typeof(COMMANDS[command]) !== 'function') {
        Env.Log.error('CHALLENGE_UNSUPPORTED_COMMAND', command);
        return cb('invalid command');
    }

    const txid = body._txid;
    delete body._txid;

    let publicKey = body.publicKey;
    // reject if they did not provide a valid public key
    if (!publicKey || typeof(publicKey) !== 'string' || publicKey.length !== 44) {
        Env.Log.error('CHALLENGE_INVALID_KEY', publicKey);
        return void cb('Invalid key');
    }

    try {
        COMMANDS[command](Env, body, function (err) {
            if (err) {
                Env.Log.error('CHALLENGE_COMMAND_EXECUTION_ERROR', {
                    command,
                    error: Util.serializeError(err),
                });
                // errors returned from commands are passed back to the client
                // as a weak precaution, we try to only send an error's message
                // if one exists. This makes it less likely that we'll respond with any
                // sensitive information in a stack trace. Ideally functions should
                // only return error messages or codes in the form of a string or number,
                // but mistakes happen.
                return void cb(err?.message || err || 'error');
            }

            let date = new Date().toISOString();

            let copy = Util.clone(body);
            copy.txid = txid;
            copy.date = date;
            delete copy._cookies;

            // Write the command and challenge to disk, because the challenge protocol
            // is interactive and the subsequent response might be handled by a different http worker
            // this makes it so we can avoid holding state in memory
            Challenge.write(Env, txid, JSON.stringify(copy), function (err) {
                if (err) {
                    Env.Log.error('CHALLENGE_WRITE_ERROR', Util.serializeError(err));
                    return void cb('Internal server error 6250');
                }
                // respond with challenge parameters
                return void cb(void 0, {
                    txid: txid,
                    date: date,
                });
            });
        }); // XXX "req" as 4th argument, check in challenge files, including plugins
    } catch (err) {
        Env.Log.error("CHALLENGE_COMMAND_THROWN_ERROR", {
            error: Util.serializeError(err),
        });
        // arbitrary error message, only intended for debugging
        return void cb('Internal server error 7692');
    }
};

// this function handles the second stage of the protocol
// (the client's response to the server's challenge)
const handleResponse = (Env, body, cb) => {

    if (Object.keys(body).some(k => !/(sig|txid|_cookies)/.test(k))) {
        Env.Log.error("CHALLENGE_RESPONSE_DEBUGGING", body);
        // we expect the response to only have two keys
        // if any more are present then the response is malformed
        return void cb('extraneous parameters');
    }


    // transaction ids are issued to the client by the server
    // they allow it to recall the full details of the challenge
    // to which the client is responding
    const txid = body.txid;

    // if no txid is present, then the server can't look up the corresponding challenge
    // the response is definitely malformed, so reject it.
    // Additionally, we expect txids to be 32 characters long (24 Uint8s as base64)
    // reject txids of any other length
    if (!txid || typeof(txid) !== 'string' || txid.length !== 32) {
        Env.Log.error('CHALLENGE_RESPONSE_BAD_TXID', body);
        return void cb("Invalid txid");
    }

    const sig = body.sig;
    if (!sig || typeof(sig) !== 'string' || sig.length !== 88) {
        Env.Log.error("CHALLENGE_RESPONSE_BAD_SIG", body);
        return void cb("Missing signature");
    }

    Challenge.read(Env, txid, function (err, text) {
        if (err) {
            Env.Log.error("CHALLENGE_READ_ERROR", {
                txid: txid,
                error: Util.serializeError(err),
            });
            return void cb("Unexpected response");
        }

        const json = Util.tryParse(text);

        if (!json) {
            Env.Log.error("CHALLENGE_PARSE_ERROR", {
                txid: txid,
            });
            return void cb("Internal server error 129");
        }

        const date = +new Date(json.date);
        const now = +new Date();
        if (!date || now - date > CHALLENGE_EXPIRY) {
            Challenge.delete(Env, txid, (err) => {
                if (err) {
                    Env.Log.error("CHALLENGE_DELETION_ERROR", {
                        txid: txid,
                        error: Util.serializeError(err),
                    });
                }
            });
            return void cb("Challenge too old");
        }

        const publicKey = json.publicKey;
        if (!publicKey || typeof(publicKey) !== 'string') {
            // This shouldn't happen, as we expect that the server
            // will have validated the key to an extent before storing the challenge
            Env.Log.error('CHALLENGE_INVALID_PUBLICKEY', {
                publicKey: publicKey,
            });
            return void cb("Invalid public key");
        }

        if (body._cookies) { json._cookies = body._cookies; }

        let action;
        try {
            action = COMMANDS[json.command].complete;
        } catch (err2) {}

        if (typeof(action) !== 'function') {
            Env.Log.error("CHALLENGE_RESPONSE_ACTION_NOT_IMPLEMENTED", json.command);
            return void cb('Not implemented');
        }

        let u8_toVerify,
            u8_sig,
            u8_publicKey;

        try {
            u8_toVerify = Util.decodeUTF8(text);
            u8_sig = Util.decodeBase64(sig);
            u8_publicKey = Util.decodeBase64(publicKey);
        } catch (err3) {
            Env.Log.error('CHALLENGE_RESPONSE_DECODING_ERROR', {
                command: json.command,
                publicKey,
                error: Util.serializeError(err3),
            });
            return void cb("decoding error");
        }

        // validate the response
        let success = Crypto.detachedVerify(u8_toVerify, u8_sig, u8_publicKey);
        if (success !== true) {
            Env.Log.error("CHALLENGE_RESPONSE_SIGNATURE_FAILURE", {
                publicKey,
            });
            return void cb('Failed signature validation');
        }

        // garbage collection can clean this up later
        Challenge.delete(Env, txid, function (err) {
            if (err) {
                Env.Log.error("CHALLENGE_DELETION_ERROR", {
                    txid: txid,
                    error: Util.serializeError(err),
                });
            }
        });

        // execute the command
        action(Env, json, function (err, content) {
            if (err) {
                Env.Log.error("CHALLENGE_RESPONSE_ACTION_ERROR", {
                    error: Util.serializeError(err),
                });
                return void cb({
                    error: 'Execution error',
                    errorCode: Util.serializeError(err)
                });
            }
            cb(void 0, content);
        }); // XXX req, res as 4th and 5th arguments
    });
};


module.exports.handle = function (Env, body, cb /*, next */) {
    initPlugins(Env);

    // we expect that the client has posted some JSON data
    if (!body) {
        return void cb('invalid request');
    }

    // we only expect responses to challenges to have a 'txid' attribute
    // further validation is performed in handleResponse
    if (body.txid) {
        return void handleResponse(Env, body, cb);
    }

    // we only expect initial requests to have a 'command' attribute
    // further validation is performed in handleCommand
    if (body.command) {
        Env.plugins?.MONITORING?.increment(`httpcmd_${body.command}`);
        return void handleCommand(Env, body, cb);
    }

    // if a request is neither a command nor a response, then reject it with an error
    cb('invalid request');
};
