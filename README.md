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

## Usage

### 1. Build project

`cargo build --release` / `cargo install --path .`

### 2. Configure environment variables

### 3. Start the client/server

### 4. Start the peer you didn't start in the previous step

### 5. Copy client public key to server, and server public key to client

### 6. Start the server

### 7. Start the client
