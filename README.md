# hopper

Minecraft reverse proxy intended for servers with encryption disabled.

## Environment Variables

|Name|Type|Default Value|Description|
|-|-|-|-|
|TCP_SERVER_ADDRESS|Socket Address|127.0.0.1:25565|TCP address to bind to in the case of the server or real Minecraft server address to connect to in the case of the client|
|PROXY_SERVER_ADDRESS|Socket Address|-|Target hopper instance to connect to. The presence of this environment variable will determine if the software runs in client or server mode. (if it is present, it will be client mode)|
|CLIENT_PRIVATE_KEY_PATH|Path|./client.key|Path of the client private key|
|CLIENT_PUBLIC_KEY_PATH|Path|./client.pub|Path of the client public key|
|SERVER_PRIVATE_KEY_PATH|Path|./server.key|Path of the server private key|
|SERVER_PUBLIC_KEY_PATH|Path|./server.pub|Path of the server public key|
|DO_ENCRYPTION|Boolean (true/false)|true|Toggle encryption for true client/false server communication|

## Usage

### 1. Build project

`cargo build --release` / `cargo install --path .`

### 2. Configure environment variables

### 3. Start the client/server

### 4. Start the peer you didn't start in the previous step

### 5. Copy client public key to server, and server public key to client

### 6. Start the server

### 7. Start the client

## How it works

### True Client Establishment
1. Server binds on TCP_SERVER_ADDRESS
2. Client connects to server specified by PROXY_SERVER_ADDRESS
3. Client sends a packet with ID 0xDEADBEEF (but signed), with the body being a random X25519 public key and an ED25519 signature of said public key signed with the private of its ED25519 keypair. Note that the length of this packet is ignored, as we don't need it, but the body must still be present.
4. After this point, we will be conversing using our simpler packet format instead of the Minecraft one.
5. Server verifies that the signature is correct and then generates its own X25519 public key and signs that public key with its private key and sends the X25519 public key & signature to the client.
6. If the key exchange is successful, this connection becomes the "true client" and all other previously connected clients are disconnected (incl. the previous true client), and further packets will be encrypted with XChaCha20Poly1305.

### False Client Establishment

1. Regular Minecraft client connects to the hopper server and sends a handshake. We differentiate between a true client establishment attempt and false client establishment attempt based on the id of this first packet.
2. Hopper server generates a random `u32`. This will be the identifier of the connection, referred to internally as a `nonce`. Note that at no point is the hopper client made aware of the true IP address. This is intentional design.
3. Hopper server tells the true client about this new connection nonce and the true client will open a new tcp connection to the true server.
4. Hopper server sends the body of the handshake packet, and will keep doing so for other packets until either side of the connection dies. The true client will do the same.

When a connection is closed on the side of the hopper server, the hopper server informs the true client that the connection has ended by telling it to remove the nonce.