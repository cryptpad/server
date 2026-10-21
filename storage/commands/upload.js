// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

const Upload = module.exports;

const Util = require("../../common/common-util");
const Pinning = require("./pin");
const nThen = require("nthen");
const Core = require("../../common/core");

Upload.status = (Env, data, _cb) => {
    const cb = Util.once(Util.mkAsync(_cb));

    const safeKey = data.safeKey;
    const filesize = data.size;

    // validate that the provided size is actually a positive number
    if (typeof(filesize) !== 'number' &&
        filesize >= 0) { return void cb('E_INVALID_SIZE'); }

    nThen((w) => {
        // if the proposed upload size is within the regular limit
        // jump ahead to the next block
        if (filesize <= Env.maxUploadSize) { return; }

        // if larger uploads aren't explicitly enabled then reject them
        if (typeof(Env.premiumUploadSize) !== 'number') {
            w.abort();
            return void cb('TOO_LARGE');
        }

        // otherwise go and retrieve info about the user's quota
        Pinning.getLimit(Env, safeKey, w((err, limit) => {
            if (err) {
                w.abort();
                return void cb("E_BAD_LIMIT");
            }

            const plan = limit[1];

            // see if they have a special plan, reject them if not
            if (plan === '') {
                w.abort();
                return void cb('TOO_LARGE');
            }

            // and that they're not over the greater limit
            if (filesize >= Env.premiumUploadSize) {
                w.abort();
                return void cb("TOO_LARGE");
            }

            // fallthrough will proceed to the next block
        }));
    }).nThen(function (w) {
        const abortAndCB = Util.both(w.abort, cb);
        Env.blobStore.status(safeKey, w((err, inProgress) => {
            // if there's an error something is weird
            if (err) { return void abortAndCB(err); }

            // we cannot upload two things at once
            if (inProgress) { return void abortAndCB(void 0, true); }
        }));
    }).nThen(function () {
        // if you're here then there are no pending uploads
        // check if you have space in your quota to upload something of this size
        Pinning.getFreeSpace(Env, safeKey, function (e, free) {
            if (e) { return void cb(e); }
            if (filesize >= free) { return cb('NOT_ENOUGH_SPACE'); }

            let user = Core.getSession(Env.blobstage, safeKey);
            user.pendingUploadSize = filesize;
            user.currentUploadSize = 0;
            user.linked = data.linked;

            cb(void 0, false);
        });
    });
};

Upload.upload = (Env, data, cb) => {
    const { safeKey, chunk } = data;
    Env.blobStore.upload(safeKey, chunk, cb);
};

Upload.cancel = (Env, data, cb) => {
    const { safeKey, size } = data;
    Env.blobStore.cancel(safeKey, size, cb);
};

const completeUpload = (owned) => {
    return (Env, data, cb) => {
        const { id, safeKey, expire }  = data;
        Env.blobStore.closeBlobstage(safeKey);
        Env.cluster.closeBlobstage(safeKey); // close blobstage in workers
        const user = Core.getSession(Env.blobstage, safeKey);
        const size = user.pendingUploadSize;
        const linked = user.linked;
        Env.worker.completeUpload(safeKey, id, Boolean(owned), size, linked, expire, cb);
    };
};

Upload.complete = completeUpload(false);
Upload.completeOwned = completeUpload(true);

Upload.cookie = (Env, data, cb) => {
    const { safeKey } = data;
    Env.blobStore.uploadCookie(safeKey, (err, cookie) => {
        if (err) { return void cb(err); }
        cb(void 0, cookie);
    });
};
