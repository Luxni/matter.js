/**
 * @license
 * Copyright 2022-2025 Matter.js Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { OnOffServer } from "#behaviors/on-off";
import { MaybePromise } from "#general";

describe("OnOffServer", () => {
    it("accepts extensions of off-only commands", () => {
        // This is a type-only test
        class MyOnOffServer extends OnOffServer {
            override on() {}
        }

        const x = {} as MyOnOffServer;

        x satisfies { on(): MaybePromise };
    });
});
