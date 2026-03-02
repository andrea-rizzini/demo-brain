import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) (globalThis as any).crypto = webcrypto;

import dotenv from 'dotenv';
import { ethers } from 'ethers';
import {
  createVerbethClient,
  deriveIdentityKeyPairWithProof,
  ExecutorFactory,
  getVerbethAddress,
  getCreationBlock,
  decryptAndExtractHandshakeKeys,
  decodeUnifiedPubKeys,
  type VerbethClient,
  type SessionStore,
  type PendingStore,
  type PendingMessage,
  type PendingStatus,
  type RatchetSession,
} from '@verbeth/sdk';
import readline from 'node:readline';

dotenv.config();

// --- Minimal ABI ---
const VERBETH_ABI = [
  'function sendMessage(bytes ciphertext, bytes32 topic, uint256 timestamp, uint256 nonce)',
  'function initiateHandshake(bytes32 recipientHash, bytes pubKeys, bytes ephemeralPubKey, bytes plaintextPayload)',
  'function respondToHandshake(bytes32 inResponseTo, bytes32 responderEphemeralR, bytes ciphertext)',
  'event Handshake(bytes32 indexed recipientHash, address indexed sender, bytes pubKeys, bytes ephemeralPubKey, bytes plaintextPayload)',
  'event HandshakeResponse(bytes32 indexed inResponseTo, address indexed responder, bytes32 responderEphemeralR, bytes ciphertext)',
  'event MessageSent(address indexed sender, bytes ciphertext, uint256 timestamp, bytes32 indexed topic, uint256 nonce)',
];

// --- In-memory stores ---
class InMemorySessionStore implements SessionStore {
  private sessions = new Map<string, RatchetSession>();
  async get(id: string) { return this.sessions.get(id) ?? null; }
  async getByInboundTopic(topic: string) {
    for (const s of this.sessions.values()) {
      if (s.currentTopicInbound === topic || s.nextTopicInbound === topic || s.previousTopicInbound === topic) return s;
    }
    return null;
  }
  async save(s: RatchetSession) { this.sessions.set(s.conversationId, s); }
  getAll() { return Array.from(this.sessions.values()); }
}

class InMemoryPendingStore implements PendingStore {
  private pending = new Map<string, PendingMessage>();
  async save(p: PendingMessage) { this.pending.set(p.id, p); }
  async get(id: string) { return this.pending.get(id) ?? null; }
  async getByTxHash(h: string) { for (const p of this.pending.values()) { if (p.txHash === h) return p; } return null; }
  async updateStatus(id: string, status: PendingStatus, txHash?: string) {
    const p = this.pending.get(id); if (p) { p.status = status; if (txHash) p.txHash = txHash; }
  }
  async delete(id: string) { this.pending.delete(id); }
  async getByConversation(cid: string) { return Array.from(this.pending.values()).filter(p => p.conversationId === cid); }
}

// --- State ---
interface ContactKeys { signingPubKey: Uint8Array; identityPubKey: Uint8Array; }
const contactInfo = new Map<string, ContactKeys>();
let pendingEphemeralSecret: Uint8Array | null = null;
let pendingKemSecret: Uint8Array | null = null;

// Agent address (from memory)
const AGENT_ADDRESS = '0x23a2ceFB34809E4D10f9F3aEA566e5809B566437';

async function main() {
  const bobKey = process.env.BOB_PRIVATE_KEY;
  if (!bobKey) {
    console.error('BOB_PRIVATE_KEY environment variable is not set.');
    console.error('Set it to Bob\'s hex private key (0x...)');
    process.exit(1);
  }

  const rpcUrl = process.env.RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com';
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new ethers.Wallet(bobKey, provider);
  const address = await wallet.getAddress();

  console.log(`\n=== Bob's Verbeth Client ===`);
  console.log(`Bob's address: ${address}`);
  console.log(`Agent address: ${AGENT_ADDRESS}`);

  // Check balance
  const balance = await provider.getBalance(address);
  console.log(`Balance: ${ethers.formatEther(balance)} ETH`);
  if (balance === 0n) {
    console.warn('\nWARNING: Bob has 0 ETH. You need Sepolia ETH to send transactions.');
    console.warn('Get some from https://sepoliafaucet.com or https://faucets.chain.link/sepolia\n');
  }

  // Derive identity
  const { keyPair: identityKeyPair, identityProof } =
    await deriveIdentityKeyPairWithProof(wallet, address);

  const verbethAddress = getVerbethAddress();
  const contract = new ethers.Contract(verbethAddress, VERBETH_ABI, wallet);
  const executor = ExecutorFactory.createEOA(contract as any);

  const sessionStore = new InMemorySessionStore();
  const pendingStore = new InMemoryPendingStore();

  const client = createVerbethClient({
    address,
    signer: wallet,
    identityKeyPair,
    identityProof,
    executor,
    sessionStore,
    pendingStore,
  });

  const network = await provider.getNetwork();
  const chainId = Number(network.chainId);
  const creationBlock = getCreationBlock(chainId);

  console.log(`Chain: ${chainId}, Verbeth contract: ${verbethAddress}`);
  console.log(`\nCommands:`);
  console.log(`  scan       — Scan for incoming handshakes from the agent`);
  console.log(`  accept     — Accept an incoming handshake from the agent`);
  console.log(`  handshake  — Initiate handshake with the agent`);
  console.log(`  complete   — Complete handshake after agent accepts`);
  console.log(`  send <msg> — Send encrypted message to the agent`);
  console.log(`  read       — Read messages from the agent`);
  console.log(`  sessions   — List active sessions`);
  console.log(`  status     — Show Bob's identity info`);
  console.log(`  quit       — Exit\n`);

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const prompt = () => rl.question('bob> ', handleCommand);

  async function handleCommand(input: string) {
    const trimmed = input.trim();
    const [cmd, ...rest] = trimmed.split(/\s+/);
    const arg = rest.join(' ');

    try {
      switch (cmd) {
        case 'scan': {
          console.log('Scanning for incoming handshakes directed to Bob...');
          const bobRecipientHash = ethers.keccak256(
            ethers.toUtf8Bytes('contact:' + address.toLowerCase())
          );
          const hsFilter = contract.filters.Handshake(bobRecipientHash);
          const hsEvents = await contract.queryFilter(hsFilter, creationBlock);
          if (hsEvents.length === 0) {
            console.log('No incoming handshakes found.');
          } else {
            console.log(`Found ${hsEvents.length} handshake(s):`);
            for (const evt of hsEvents) {
              const sender = (evt as any).args[1];
              console.log(`  from: ${sender} (block ${evt.blockNumber}, tx: ${evt.transactionHash})`);
            }
            console.log('\nUse "accept" to accept the handshake from the agent.');
          }
          break;
        }

        case 'accept': {
          console.log(`Scanning for handshake from agent ${AGENT_ADDRESS}...`);
          const recipientHash = ethers.keccak256(
            ethers.toUtf8Bytes('contact:' + address.toLowerCase())
          );
          const acceptFilter = contract.filters.Handshake(recipientHash);
          const acceptEvents = await contract.queryFilter(acceptFilter, creationBlock);
          const agentHs = acceptEvents
            .filter((e: any) => e.args[1].toLowerCase() === AGENT_ADDRESS.toLowerCase())
            .pop();
          if (!agentHs) {
            console.log('No handshake from agent found. Has the agent initiated one?');
            break;
          }

          const initiatorEphemeralPubKey = ethers.getBytes((agentHs as any).args[3]);

          // Extract agent's signing + identity keys from pubKeys field
          const pubKeysBytes = ethers.getBytes((agentHs as any).args[2]);
          const decoded = decodeUnifiedPubKeys(pubKeysBytes);
          if (decoded) {
            contactInfo.set(AGENT_ADDRESS.toLowerCase(), {
              signingPubKey: decoded.signingPubKey,
              identityPubKey: decoded.identityPubKey,
            });
          }

          console.log('Accepting handshake...');
          const result = await client.acceptHandshake(
            initiatorEphemeralPubKey,
            'Bob accepts!'
          );
          console.log('Waiting for tx confirmation...');
          const receipt = await result.tx.wait();

          const session = client.createResponderSession({
            contactAddress: AGENT_ADDRESS,
            responderEphemeralSecret: result.responderEphemeralSecret,
            responderEphemeralPublic: result.responderEphemeralPublic,
            initiatorEphemeralPubKey,
            salt: result.salt,
            kemSharedSecret: result.kemSharedSecret,
          });
          await sessionStore.save(session);

          console.log(`Handshake accepted! tx: ${receipt.hash}`);
          console.log(`Session established: ${session.conversationId}`);
          console.log('Now tell the agent to complete (POST /verbeth/handshake/complete)');
          console.log('Then you can exchange messages with "send" and "read".');
          break;
        }

        case 'handshake': {
          console.log(`Initiating handshake with agent ${AGENT_ADDRESS}...`);
          const { tx, ephemeralKeyPair, kemKeyPair } =
            await client.sendHandshake(AGENT_ADDRESS, 'Hello from Bob!');
          console.log('Waiting for tx confirmation...');
          const receipt = await tx.wait();
          pendingEphemeralSecret = ephemeralKeyPair.secretKey;
          pendingKemSecret = kemKeyPair.secretKey;
          console.log(`Handshake sent! tx: ${receipt.hash}`);
          console.log('Now ask the agent to accept (POST /verbeth/handshake/accept)');
          console.log('Then run "complete" here.');
          break;
        }

        case 'complete': {
          if (!pendingEphemeralSecret || !pendingKemSecret) {
            console.log('No pending handshake. Run "handshake" first.');
            break;
          }
          console.log('Scanning for handshake response from agent...');
          const filter = contract.filters.HandshakeResponse();
          const hsrEvents = await contract.queryFilter(filter, creationBlock);
          const candidates = hsrEvents.filter(
            (e: any) => e.args[1].toLowerCase() === AGENT_ADDRESS.toLowerCase()
          );
          if (candidates.length === 0) {
            console.log('No handshake response from agent yet. Has the agent accepted?');
            break;
          }

          let matched: any = null;
          let extractedKeys: any = null;
          for (const evt of candidates) {
            const ct = typeof (evt as any).args[3] === 'string'
              ? (evt as any).args[3]
              : ethers.hexlify((evt as any).args[3]);
            const keys = decryptAndExtractHandshakeKeys(ct, pendingEphemeralSecret);
            if (keys) { matched = evt; extractedKeys = keys; break; }
          }
          if (!matched || !extractedKeys) {
            console.log('Could not decrypt any handshake response. Agent may not have accepted yet.');
            break;
          }

          contactInfo.set(AGENT_ADDRESS.toLowerCase(), {
            signingPubKey: extractedKeys.signingPubKey,
            identityPubKey: extractedKeys.identityPubKey,
          });

          const session = client.createInitiatorSessionFromHsr({
            contactAddress: AGENT_ADDRESS,
            myEphemeralSecret: pendingEphemeralSecret,
            myKemSecret: pendingKemSecret,
            hsrEvent: {
              inResponseToTag: (matched as any).args[0] as `0x${string}`,
              responderEphemeralPubKey: extractedKeys.ephemeralPubKey,
              kemCiphertext: extractedKeys.kemCiphertext,
            },
          });
          await sessionStore.save(session);
          pendingEphemeralSecret = null;
          pendingKemSecret = null;
          console.log(`Handshake complete! Session: ${session.conversationId}`);
          console.log('You can now send messages with "send <message>"');
          break;
        }

        case 'send': {
          if (!arg) { console.log('Usage: send <message>'); break; }
          const sessions = sessionStore.getAll();
          const session = sessions.find(
            s => s.contactAddress.toLowerCase() === AGENT_ADDRESS.toLowerCase()
          );
          if (!session) { console.log('No session with agent. Complete handshake first.'); break; }
          console.log('Sending encrypted message...');
          const result = await client.sendMessage(session.conversationId, arg);
          console.log(`Message sent! tx: ${result.txHash}, topic: ${result.topic}`);
          break;
        }

        case 'read': {
          const sessions = sessionStore.getAll();
          const session = sessions.find(
            s => s.contactAddress.toLowerCase() === AGENT_ADDRESS.toLowerCase()
          );
          if (!session) { console.log('No session with agent. Complete handshake first.'); break; }

          const contact = contactInfo.get(AGENT_ADDRESS.toLowerCase());
          if (!contact) { console.log('No contact keys for agent.'); break; }

          const topics = [session.currentTopicInbound, session.nextTopicInbound, session.previousTopicInbound].filter(Boolean) as string[];
          let found = 0;
          for (const topic of topics) {
            const msgFilter = contract.filters.MessageSent(null, null, null, topic);
            const events = await contract.queryFilter(msgFilter, creationBlock);
            for (const evt of events) {
              try {
                const payload = ethers.getBytes((evt as any).args[1]);
                const decrypted = await client.decryptMessage(topic, payload, contact.signingPubKey, false);
                if (decrypted) {
                  console.log(`[Agent]: ${decrypted.plaintext}`);
                  found++;
                }
              } catch { /* skip */ }
            }
          }
          if (found === 0) console.log('No messages from agent yet.');
          break;
        }

        case 'sessions': {
          const all = sessionStore.getAll();
          if (all.length === 0) { console.log('No active sessions.'); break; }
          for (const s of all) {
            console.log(`  ${s.conversationId} <-> ${s.contactAddress} (epoch ${s.topicEpoch}, sent: ${s.sendingMsgNumber}, recv: ${s.receivingMsgNumber})`);
          }
          break;
        }

        case 'status': {
          console.log(`Address: ${address}`);
          console.log(`Signing pub: ${Buffer.from(client.identityKeyPairInstance.signingPublicKey).toString('hex')}`);
          console.log(`Identity pub: ${Buffer.from(client.identityKeyPairInstance.publicKey).toString('hex')}`);
          console.log(`Pending handshake: ${pendingEphemeralSecret ? 'yes' : 'no'}`);
          console.log(`Sessions: ${sessionStore.getAll().length}`);
          break;
        }

        case 'quit':
        case 'exit':
          rl.close();
          process.exit(0);

        default:
          if (cmd) console.log(`Unknown command: ${cmd}`);
      }
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
    }

    prompt();
  }

  prompt();
}

main().catch(err => { console.error('Fatal:', err); process.exit(1); });
