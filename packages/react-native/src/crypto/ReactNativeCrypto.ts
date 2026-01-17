/**
 * @license
 * Copyright 2022-2026 Matter.js Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { Bytes, Crypto, CryptoError, EcdsaSignature, Entropy, Environment, StandardCrypto, WebCrypto } from "#general";
import { Buffer } from "@craftzdog/react-native-buffer";
import QuickCrypto from "react-native-quick-crypto";

// The default export from QuickCrypto should be compatible with the standard `crypto` object but the type system
// seems confused by CJS exports.  Use a forced cast to correct types.
const crypto = QuickCrypto as unknown as typeof QuickCrypto.default;

// QuickCrypto's `install()` function is documented as optional but QuickCrypto references it as a global in its subtle
// implementation, so we can't avoid mucking with global scope (as of QuickCrypto 0.7.6)
if (!("Buffer" in globalThis)) {
    (globalThis as unknown as { Buffer: typeof Buffer }).Buffer = Buffer;
}

const SIGNATURE_ALGORITHM = <EcdsaParams>{
    name: "ECDSA",
    namedCurve: "P-256",
    hash: { name: "SHA-256" },
};

/**
 * Crypto implementation for React Native should work with a WebCrypto basis with 1.x
 */
export class ReactNativeCrypto extends StandardCrypto {
    override implementationName = "ReactNativeCrypto";
    #subtle: SubtleCrypto;

    constructor() {
        super(crypto as unknown as WebCrypto);
        this.#subtle = (crypto as unknown as WebCrypto).subtle;
    }

    static override provider() {
        return new ReactNativeCrypto();
    }

    override async signEcdsa(key: JsonWebKey, data: Bytes | Bytes[]) {
        if (Array.isArray(data)) {
            data = Bytes.concat(...data);
        }

        const { crv, kty, d, x, y } = key;

        key = {
            kty,
            crv,
            d,
            x,
            y,
            ext: true, // Required by some subtle implementations to sign
            key_ops: ["sign"],
        };

        const subtleKey = await this.importKey("jwk", key, SIGNATURE_ALGORITHM, false, ["sign"]);
        try {
            const derSignature = await this.#subtle.sign(SIGNATURE_ALGORITHM, subtleKey, Bytes.exclusive(data));
            return new EcdsaSignature(Bytes.of(derSignature), "der");
        } catch (e) {
            throw new CryptoError(`Signature sign failed: ${e}`);
        }
    }

    override async verifyEcdsa(key: JsonWebKey, data: Bytes, signature: EcdsaSignature) {
        const { crv, kty, x, y } = key;
        const publicKey = { crv, kty, x, y };
        const subtleKey = await this.importKey("jwk", publicKey, SIGNATURE_ALGORITHM, false, ["verify"]);

        try {
            const verified = await this.#subtle.verify(
                SIGNATURE_ALGORITHM,
                subtleKey,
                Bytes.exclusive(signature.der),
                Bytes.exclusive(data),
            );

            if (!verified) {
                throw new Error("Signature verification failed");
            }
        } catch (e) {
            throw new CryptoError(`Signature verification failed: ${e}`);
        }
    }
}

{
    const rnCrypto = new ReactNativeCrypto();
    Environment.default.set(Entropy, rnCrypto);
    Environment.default.set(Crypto, rnCrypto);
}
