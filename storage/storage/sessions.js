// SPDX-FileCopyrightText: 2023 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const Path = require("node:path");
const Crypto = require('node:crypto');
const Basic = require("../../common/storage/basic");
const Util = require("../../common/common-util");
const Core = require("../../common/core");

const Sessions = module.exports;
/*  This module manages storage for per-acccount session tokens - currently assumed to be
    JSON Web Tokens (JWTs).

    Decisions about what goes into each of those JWTs happens upstream, so the storage
    itself is relatively unopinionated.

    The key things to understand are:

* valid sessions allow the holder of a given JWT to access a given "login block"
* JWTs are signed with a key held in the server's memory. If that key leaks then it should be rotated (with the SET_BEARER_SECRET decree) to invalidate all existing JWTs. Under these conditions then all tokens signed with the old key can be removed. Garbage collection of these older tokens is not implemented.
* it is expected that any given login-block can have multiple active sessions (for different devices, or if their browser clears its cache automatically). All sessions for a given block are stored in a per-user directory which is intended to make listing or iterating over them simple.
* It could be desirable to expose the list of sessions to the relevant user and allow them to revoke sessions individually or en-masse, though this is not currently implemented.

*/

const pathFromId = (Env, id, ref) => {
    if (!Basic.isValidId(ref)) { return; }
    if (!id || typeof(id) !== 'string') { return; }
    id = Util.escapeKeyCharacters(id);
    if (!Basic.isValidId(id)) { return; }
    return Path.join(Env.paths.base, "sessions", id.slice(0, 2), id, ref);
};

Sessions.randomId = () => Util.encodeBase64(Crypto.randomBytes(24)).replace(/\//g, '-');

Sessions.read = (Env, id, ref, cb, noRedirect) => {
    if (!noRedirect && !Core.checkStorage(Env, id, 'SESSIONS_CMD', {
        cmd: 'READ', blockId: id, session: ref
    }, cb)) { return; }

    const path = pathFromId(Env, id, ref);
    Basic.read(Env, path, cb);
};

Sessions.write = (Env, id, ref, data, cb) => {
    const path = pathFromId(Env, id, ref);
    Basic.write(Env, path, data, cb);
};

Sessions.delete = (Env, id, ref, cb, noRedirect) => {
    if (!noRedirect && !Core.checkStorage(Env, id, 'SESSIONS_CMD', {
        cmd: 'DELETE', blockId: id, session: ref
    }, cb)) { return; }

    const path = pathFromId(Env, id, ref);
    Basic.delete(Env, path, cb);
};

Sessions.update = (Env, id, oldId, ref, dataStr, cb) => {
    const data = Util.tryParse(dataStr);
    Sessions.read(Env, oldId, ref, (err, oldData) => {
        let content = Util.tryParse(oldData) || {};
        Object.keys(data || {}).forEach((type) => {
            content[type] = data[type];
        });
        Sessions.delete(Env, oldId, ref, () => {
            Sessions.write(Env, id, ref, JSON.stringify(content), cb);
        });
    });
};

Sessions.deleteUser = (Env, id,  cb) => {
    if (!id || typeof(id) !== 'string') { return; }
    id = Util.escapeKeyCharacters(id);
    const dirPath = Path.join(Env.paths.base, "sessions", id.slice(0, 2), id);

    Basic.readDir(Env, dirPath, (err, files) => {
        const checkContent = !files || (Array.isArray(files) && files.every((file) => {
            return file && file.length === 32;
        }));
        if (!checkContent) { return void cb('INVALID_SESSIONS_DIR'); }
        Basic.deleteDir(Env, dirPath, cb);
    });
};

