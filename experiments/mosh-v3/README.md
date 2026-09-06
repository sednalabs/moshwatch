<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Mosh v3 crypto prototype

This directory contains a deliberately isolated OpenSSL-backed prototype for the transport-crypto design in [`docs/mosh-v3-transport-crypto.md`](../../docs/mosh-v3-transport-crypto.md).

It is **not** wired into `mosh-client` or `mosh-server` yet and does not change the default Mosh v2 wire protocol.

The prototype currently proves the small cryptographic substrate we want before touching Mosh's network state machine:

- 256-bit SSH bootstrap secret and canonical unpadded base64 representation
- HKDF-SHA-256 extraction and domain-separated directional traffic secrets
- move-only traffic-secret and traffic-key objects with explicit cleansing
- ChaCha20-Poly1305 through OpenSSL EVP
- deterministic 96-bit per-packet nonces from an epoch IV plus Mosh packet sequence
- fixed 18-byte v3 header authenticated as AEAD associated data
- hash-ratchet traffic-secret update
- tests for round trip, direction separation, header/ciphertext tampering, nonce separation, rekey separation, and bootstrap encoding

Build the standalone test on an OpenSSL development host:

```sh
c++ -std=c++11 -Wall -Wextra -Werror -pedantic \
  crypto_v3.cc crypto_v3_test.cc -lcrypto -o crypto_v3_test
./crypto_v3_test
```

The next slice is the epoch/acknowledgement state machine, followed by an opt-in v3 bootstrap and packet framing path in the vendored Mosh client/server. Production wiring should not begin until the state-machine tests cover loss, reordering, long disconnects, and roaming.
