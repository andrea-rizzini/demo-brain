# demo-brain

A TEE-based agent running on EigenLayer Cloud with end-to-end encrypted messaging via [Verbeth](https://verbeth.org).

The agent exposes a Fastify HTTP server with wallet operations, an attested randomness beacon, and Verbeth messaging endpoints for establishing encrypted channels with any Ethereum address.

## Quickstart

### 1. Install dependencies

```bash
npm install
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and set:

```
RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
BOB_PRIVATE_KEY=0x...   # private key for the Bob test client
```

The agent's `MNEMONIC` is auto-provided by KMS at runtime in the TEE. For local testing, set it manually in `.env`.

### 3. Build

```bash
npm run build
```

### 4. Run the agent locally

```bash
MNEMONIC="your twelve word mnemonic phrase here" npm start
```

### 5. Run Bob's client

In a separate terminal:

```bash
npm run bob
```

### 6. Full messaging round

**Agent initiates handshake to Bob:**

```bash
curl -s -X POST http://localhost:8080/verbeth/handshake/initiate -H "Content-Type: application/json" -d '{"to": "<bob-address>", "message": "Hello Bob!"}'
```

**Bob scans and accepts (in Bob's CLI):**

```
bob> scan
bob> accept
```

**Agent completes the handshake:**

```bash
curl -s -X POST http://localhost:8080/verbeth/handshake/complete -H "Content-Type: application/json" -d '{"from": "<bob-address>"}'
```

**Bob sends a message:**

```
bob> send Hello from Bob!
```

**Agent reads messages:**

```bash
curl -s http://localhost:8080/verbeth/messages
```

**Agent sends a reply:**

```bash
curl -s -X POST http://localhost:8080/verbeth/send -H "Content-Type: application/json" -d '{"to": "<bob-address>", "message": "Reply from agent!"}'
```

**Bob reads the reply:**

```
bob> read
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `MNEMONIC` | Yes (agent) | BIP39 mnemonic for the agent signer (`m/44'/60'/0'/0/0`). Auto-provided by KMS in TEE. |
| `RPC_URL` | No | Sepolia RPC endpoint. Defaults to `https://rpc.sepolia.org`. |
| `VERBETH_RPC_URL` | No | Separate RPC for Verbeth. Falls back to `RPC_URL`. |
| `BOB_PRIVATE_KEY` | Yes (Bob) | Hex private key for the Bob test client. |
| `PORT` | No | Server port. Defaults to `8080`. |

## Agent API

### Core endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/wallet` | Agent address and ETH balance |
| `POST` | `/send` | Send ETH: `{"to": "0x...", "amount": "0.01"}` |
| `GET` | `/random` | Attested randomness beacon |

### Verbeth messaging endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/verbeth/status` | Agent identity info and session count |
| `GET` | `/verbeth/sessions` | List active sessions |
| `POST` | `/verbeth/handshake/initiate` | Initiate handshake: `{"to": "0x...", "message": "..."}` |
| `GET` | `/verbeth/handshake/incoming` | List pending incoming handshakes. Optional `?fromBlock=` |
| `POST` | `/verbeth/handshake/accept` | Accept incoming handshake: `{"from": "0x...", "fromBlock?": 123}` |
| `POST` | `/verbeth/handshake/complete` | Complete handshake as initiator: `{"from": "0x...", "fromBlock?": 123}` |
| `POST` | `/verbeth/send` | Send encrypted message: `{"to": "0x...", "message": "..."}` |
| `GET` | `/verbeth/messages` | Read incoming messages. Optional `?from=0x...&fromBlock=` |

## Bob's CLI Commands

| Command | Description |
|---|---|
| `scan` | Scan for incoming handshakes from the agent |
| `accept` | Accept an incoming handshake from the agent |
| `handshake` | Initiate handshake with the agent |
| `complete` | Complete handshake after agent accepts |
| `send <msg>` | Send encrypted message to the agent |
| `read` | Read and decrypt messages from the agent |
| `sessions` | List active sessions |
| `status` | Show Bob's identity info |
| `quit` | Exit |

## Handshake Flows

Either party can initiate. The flow is always three steps:

**Initiator starts -> Responder accepts -> Initiator completes**

After completion, both sides have a shared ratchet session and can exchange end-to-end encrypted messages. Messages are scanned by topic (not sender address) using the Verbeth double ratchet protocol.

## Deployment

### Prerequisites

- Docker
- ETH on Sepolia (for deployment transactions and on-chain messaging)
- `ecloud` CLI installed (`@layr-labs/ecloud-cli`)

### Build and push Docker image

```bash
docker build -t <dockerhub-username>/demo-brain:latest .
docker push <dockerhub-username>/demo-brain:latest
```

### Deploy

```bash
ecloud compute app deploy --image-ref <dockerhub-username>/demo-brain:latest --name demo-brain
```

### Upgrade

```bash
docker build -t <dockerhub-username>/demo-brain:latest .
docker push <dockerhub-username>/demo-brain:latest
ecloud compute app upgrade demo-brain --image-ref <dockerhub-username>/demo-brain:latest
```

### Management

```bash
ecloud compute app list                    # List all apps
ecloud compute app info demo-brain         # Get app details
ecloud compute app logs demo-brain         # View logs
ecloud compute app start demo-brain        # Start stopped app
ecloud compute app stop demo-brain         # Stop running app
ecloud compute app terminate demo-brain    # Terminate app permanently
```

## Technical Details

- **Verbeth contract**: `0x82C9c5475D63e4C9e959280e9066aBb24973a663` (deterministic CREATE2, same on all chains)
- **Sepolia creation block**: 10340254 (chain 11155111)
- **Agent address**: `0x23a2ceFB34809E4D10f9F3aEA566e5809B566437`
- Sessions are stored in-memory (lost on restart, acceptable for demo)
- Uses ethers v6 for Verbeth SDK, viem for core wallet operations
