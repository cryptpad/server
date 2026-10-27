// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 XWiki CryptPad Team <contact@cryptpad.org> and contributors
const Constants = require('../common/constants.js');

var HK = module.exports;

const {
    STANDARD_CHANNEL_LENGTH,
    ADMIN_CHANNEL_LENGTH,
    BLOB_ID_LENGTH,
    publicKeyLength
} = Constants;

HK.STANDARD_CHANNEL_LENGTH = STANDARD_CHANNEL_LENGTH;
HK.ADMIN_CHANNEL_LENGTH = ADMIN_CHANNEL_LENGTH;
HK.BLOB_ID_LENGTH = BLOB_ID_LENGTH;


/*  getHash
    * this function slices off the leading portion of a message which is
      most likely unique
    * these "hashes" are used to identify particular messages in a channel's history
    * clients store "hashes" either in memory or in their drive to query for new messages:
      * when reconnecting to a pad
      * when connecting to chat or a mailbox
    * thus, we can't change this function without invalidating client data which:
      * is encrypted clientside
      * can't be easily migrated
    * don't break it!
*/
HK.getHash = function (msg, Log) {
    if (typeof(msg) !== 'string') {
        if (Log) {
            Log.warn('HK_GET_HASH', 'getHash() called on ' + typeof(msg) + ': ' + msg);
        }
        return '';
    }
    return msg.slice(0,64);
};

/*  sliceCpIndex
    returns a list of all checkpoints which might be relevant for a client connecting to a session

    * if there are two or fewer checkpoints, return everything you have
    * if there are more than two
      * return at least two
      * plus any more which were received within the last 100 messages

    This is important because the additional history is what prevents
    clients from forking on checkpoints and dropping forked history.

*/
HK.sliceCpIndex = function (cpIndex, line) {
    // Remove "old" checkpoints (cp sent before 100 messages ago)
    const minLine = Math.max(0, (line - 100));
    let start = cpIndex.slice(0, -2);
    const end = cpIndex.slice(-2);
    start = start.filter(function (obj) {
        return obj.line > minLine;
    });
    return start.concat(end);
};

HK.isMetadataMessage = function (parsed) {
    return Boolean(parsed && parsed.channel);
};

const decodeBase64 = function(string) {
    return Buffer.from(string, 'base64');
};

// validateKeyStrings supplied by clients must decode to 32-byte Uint8Arrays
HK.isValidValidateKeyString = key => {
    try {
        return typeof (key) === 'string' &&
            decodeBase64(key).length === publicKeyLength;
    } catch {
        return false;
    }
};

/*  Remove from the map any byte offsets which are below
    the lowest offset you'd like to preserve
    (probably the oldest checkpoint */
HK.trimMapByOffset = function (map, offset) {
    if (!offset) { return; }
    for (let k in map) {
        if (map[k] < offset) {
            delete map[k];
        }
    }
};

/*  checkOffsetMap

Sorry for the weird function --ansuz
→ No Worries

This should be almost equivalent to `Object.keys(map).length` except
that is will use less memory by not allocating space for the temporary array.
Beyond that, it returns length * -1 if any of the members of the map
are not in ascending order. The function for removing older members of the map
loops over elements in order and deletes them, so ordering is important!

*/
HK.checkOffsetMap = function (map) {
    var prev = 0;
    var cur;
    var ooo = 0; // out of order
    var count = 0;
    for (let k in map) {
        count++;
        cur = map[k];
        if (!ooo && prev > cur) { ooo = true; }
        prev = cur;
    }
    return ooo ? count * -1: count;
};

/* Pass the map and the number of elements it contains */
HK.trimOffsetByOrder = function (map, n) {
    var toRemove = Math.max(n - 50, 0);
    var i = 0;
    for (let k in map) {
        if (i >= toRemove) { return; }
        i++;
        delete map[k];
    }
};

HK.listAllowedUsers = metadata => {
    return (metadata.owners || []).concat((metadata.allowed || []));
};

HK.isUserSessionAllowed = (allowed, authKeys) => {
    if (!authKeys) { return false; }
    for (var unsafeKey in authKeys) {
        if (allowed.includes(unsafeKey)) {
            return true;
        }
    }
    return false;
};

