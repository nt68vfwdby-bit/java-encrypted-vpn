# java-socks5-vpn

A simple encrypted TCP tunnel and local SOCKS5 proxy written in standard Java without external libraries. 

Built this project to practice socket programming, multithreading, and Java's built-in cryptography APIs (`javax.crypto`).

## How it works

1. `VpnClient` listens locally (default `127.0.0.1:1085`) and handles standard SOCKS5 `CONNECT` requests.
2. When an app connects, the client opens a TCP socket to `VpnServer` and runs a handshake.
3. Both sides verify a pre-shared secret using `HMAC-SHA256` (compared in constant time via `MessageDigest.isEqual`) and derive a one-time session key using ECDH (`secp256r1`).
4. All traffic is framed with a monotonic sequence number and encrypted with `AES-256-GCM` (12-byte random IV per packet). If a packet is modified or replayed out of order, the connection drops.

## Layout


src/
├── crypto/SecureChannel.java   # ECDH key exchange, HMAC check, AES-GCM framing
├── server/VpnServer.java       # Multi-threaded exit node
└── client/VpnClient.java       # Local SOCKS5 listener

## Usage

Compile everything into `out/`:

mkdir -p out
javac -d out src/crypto/SecureChannel.java src/server/VpnServer.java src/client/VpnClient.java

Start the server (port and secret are optional, defaults to `9090`):

java -cp out server.VpnServer 9090 my_secret_key

Start the local client (defaults to local port `1085`, server `127.0.0.1:9090`):

java -cp out client.VpnClient 1085 127.0.0.1 9090 my_secret_key

Test with `curl` (using `--socks5-hostname` so DNS resolves on the server side):

curl --socks5-hostname 127.0.0.1:1085 -I https://example.com

## Limitations

- Only supports TCP `CONNECT` (no UDP associate yet).
- Uses a pre-shared secret for initial authentication rather than asymmetric client certificates.
