# TG WS Proxy Android

Android/Java port of the architecture of Flowseal/tg-ws-proxy.

Implemented:
- local MTProto proxy listener on `127.0.0.1:1443`;
- 64-byte MTProto obfuscation handshake parsing;
- DC/media detection;
- AES-CTR client-side secret decryption/re-encryption;
- generation of the relay obfuscation init;
- TLS + WebSocket connection to Telegram DC IP with Telegram WS hostname/SNI;
- randomized WS endpoint selection;
- Cloudflare-domain refresh from the upstream project list;
- CF WS fallback;
- direct TCP fallback;
- binary WebSocket framing;
- foreground Android service;
- `tg://proxy?...&secret=dd...` link generation;
- simple UI and persistent log.

Important:
This is a clean-room Java implementation of the protocol flow, not a byte-for-byte translation of the Python source. The upstream project evolves, so the endpoint list and protocol constants should be periodically checked against the upstream repository.

Upstream project: https://github.com/Flowseal/tg-ws-proxy
License: MIT. See the upstream repository for the original copyright/license text.

Build:
1. Open this directory in Android Studio.
2. Let Gradle sync.
3. Build/install the app.
4. Start the proxy.
5. In Telegram Android add an MTProto proxy with:
   server: 127.0.0.1
   port: 1443
   secret: the value shown in the app.

For a device where Telegram itself cannot use a loopback MTProto proxy, the Android app would need to be extended with a VPN/TUN mode; this project intentionally keeps the same local-MTProto-proxy model as the desktop project.
