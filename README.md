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
|MAX_PROCESSING_CONSOLIDATION|usize|usize::MAX|(experimental, this may be wrong!) Maximum amount of events we can receive in bulk. This affects all proxy messages and outbound minecraft packets. Using a value of 1 may slightly decrease latency, but is likely to decrease performance with a high amount of data transfer| 
|FORK_COUNT|usize|15|How many additional (fork) connections to spawn. Note that there will *always* be at least one connection spawned, so in truth FORK_COUNT + 1 connections will be used for data transfer. Note that this needs to be the same on both the client and server otherwise you will run into deserialization issues|
|FORK_ESTABLISH_INTERVAL|u64|10|How many milliseconds to wait before establishing a new fork connection on startup|

## Usage

### 1. Build project

`cargo build --release` / `cargo install --path .`

### 2. Configure environment variables

### 3. Start the client/server

### 4. Start the peer you didn't start in the previous step

### 5. Copy client public key to server, and server public key to client

### 6. Start the server

### 7. Start the client