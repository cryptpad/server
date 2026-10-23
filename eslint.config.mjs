// SPDX-FileCopyrightText: 2026 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import globals from "globals";
import { defineConfig } from "eslint/config";


const rules = {
    indent: ["off", 4],
    "linebreak-style": ["off", "unix"],
    quotes: ["off", "single"],
    semi: ["error", "always"],
    eqeqeq: ["error", "always"],
    "no-irregular-whitespace": ["off"],
    "no-self-assign": ["off"],
    "no-empty": ["off"],
    "no-useless-escape": ["off"],
    "no-extra-boolean-cast": ["off"],
    "no-prototype-builtins": ["off"],
    "no-use-before-define": ["error"],
    "no-undef": ["error"],
    "no-unused-vars": [
        "error",
        {
            caughtErrors: "none"
        }
    ]
};

export default defineConfig([{
    files: ["**/*.{js,mjs,cjs}"],
    ignores: [
        "scripts/**", "build/**",
        "plugins/*/client/**", "common/common-util.js",
        "common/keys.js"
    ],
    languageOptions: { globals: globals.node },
    rules
}, {
    files: ["plugins/*/client/**.{js,mjs,cjs}"],
    languageOptions: {
        globals: { ...globals.browser, ...globals.amd }
    },
    rules
}, {
    files: ["common/common-util.js", "common/keys.js"],
    languageOptions: {
        globals: { ...globals.node, ...globals.browser, ...globals.amd }
    },
    rules
}]);
