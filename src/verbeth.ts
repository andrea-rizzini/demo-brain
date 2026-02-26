import { ethers } from 'ethers';
import {
  createVerbethClient,
  deriveIdentityKeyPairWithProof,
  ExecutorFactory,
  getVerbethAddress,
  type VerbethClient,
  type SessionStore,
  type PendingStore,
  type PendingMessage,
  type PendingStatus,
  type PendingContactEntry,
} from '@verbeth/sdk';
import type { RatchetSession } from '@verbeth/sdk';

// Minimal ABI for event scanning (the SDK handles tx submission via Executor)
const VERBETH_ABI = [
  'function sendMessage(bytes ciphertext, bytes32 topic, uint256 timestamp, uint256 nonce)',
  'function initiateHandshake(bytes32 recipientHash, bytes pubKeys, bytes ephemeralPubKey, bytes plaintextPayload)',
  'function respondToHandshake(bytes32 inResponseTo, bytes32 responderEphemeralR, bytes ciphertext)',
  'event Handshake(bytes32 indexed recipientHash, address indexed sender, bytes pubKeys, bytes ephemeralPubKey, bytes plaintextPayload)',
  'event HandshakeResponse(bytes32 indexed inResponseTo, address indexed responder, bytes32 responderEphemeralR, bytes ciphertext)',
  'event MessageSent(address indexed sender, bytes ciphertext, uint256 timestamp, bytes32 indexed topic, uint256 nonce)',
];

// --- In-memory SessionStore ---
class InMemorySessionStore implements SessionStore {
  private sessions = new Map<string, RatchetSession>();

  async get(conversationId: string): Promise<RatchetSession | null> {
    return this.sessions.get(conversationId) ?? null;
  }

  async getByInboundTopic(topic: string): Promise<RatchetSession | null> {
    for (const session of this.sessions.values()) {
      if (
        session.currentTopicInbound === topic ||
        session.nextTopicInbound === topic ||
        session.previousTopicInbound === topic
      ) {
        return session;
      }
    }
    return null;
  }

  async save(session: RatchetSession): Promise<void> {
    this.sessions.set(session.conversationId, session);
  }

  getAll(): RatchetSession[] {
    return Array.from(this.sessions.values());
  }
}

// --- In-memory PendingStore ---
class InMemoryPendingStore implements PendingStore {
  private pending = new Map<string, PendingMessage>();

  async save(p: PendingMessage): Promise<void> {
    this.pending.set(p.id, p);
  }

  async get(id: string): Promise<PendingMessage | null> {
    return this.pending.get(id) ?? null;
  }

  async getByTxHash(txHash: string): Promise<PendingMessage | null> {
    for (const p of this.pending.values()) {
      if (p.txHash === txHash) return p;
    }
    return null;
  }

  async updateStatus(id: string, status: PendingStatus, txHash?: string): Promise<void> {
    const p = this.pending.get(id);
    if (p) {
      p.status = status;
      if (txHash) p.txHash = txHash;
    }
  }

  async delete(id: string): Promise<void> {
    this.pending.delete(id);
  }

  async getByConversation(conversationId: string): Promise<PendingMessage[]> {
    return Array.from(this.pending.values()).filter(
      (p) => p.conversationId === conversationId
    );
  }
}

// --- Pending handshake secrets (keyed by lowercase recipient address) ---
export interface PendingHandshake {
  ephemeralSecret: Uint8Array;
  kemSecret: Uint8Array;
}

const pendingHandshakes = new Map<string, PendingHandshake>();

export function savePendingHandshake(
  address: string,
  ephemeralSecret: Uint8Array,
  kemSecret: Uint8Array
) {
  pendingHandshakes.set(address.toLowerCase(), { ephemeralSecret, kemSecret });
}

export function getPendingHandshake(address: string): PendingHandshake | undefined {
  return pendingHandshakes.get(address.toLowerCase());
}

export function deletePendingHandshake(address: string) {
  pendingHandshakes.delete(address.toLowerCase());
}

export function getAllPendingContacts(): PendingContactEntry[] {
  return Array.from(pendingHandshakes.entries()).map(([addr, h]) => ({
    address: addr,
    handshakeEphemeralSecret: h.ephemeralSecret,
    kemSecretKey: h.kemSecret,
  }));
}

// --- Initialization ---
export interface VerbethInstance {
  client: VerbethClient;
  provider: ethers.JsonRpcProvider;
  contract: ethers.Contract;
  sessionStore: InMemorySessionStore;
  pendingStore: InMemoryPendingStore;
  address: string;
  chainId: number;
}

export async function initVerbeth(
  mnemonic: string,
  rpcUrl: string
): Promise<VerbethInstance> {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = ethers.Wallet.fromPhrase(mnemonic).connect(provider);
  const address = await wallet.getAddress();

  // Derive Verbeth identity keys
  const { keyPair: identityKeyPair, identityProof } =
    await deriveIdentityKeyPairWithProof(wallet, address);

  // Create contract + executor
  const verbethAddress = getVerbethAddress();
  const contract = new ethers.Contract(verbethAddress, VERBETH_ABI, wallet);
  const executor = ExecutorFactory.createEOA(contract as any);

  // Create stores
  const sessionStore = new InMemorySessionStore();
  const pendingStore = new InMemoryPendingStore();

  // Create client
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

  console.log(`Verbeth initialized — address: ${address}, chainId: ${chainId}`);
  console.log(`Verbeth contract: ${verbethAddress}`);

  return { client, provider, contract, sessionStore, pendingStore, address, chainId };
}

// --- Event scanning helpers ---

export async function scanHandshakeEvents(
  contract: ethers.Contract,
  recipientAddress: string,
  fromBlock: number
) {
  const recipientHash = ethers.keccak256(
    ethers.toUtf8Bytes('contact:' + recipientAddress.toLowerCase())
  );
  const filter = contract.filters.Handshake(recipientHash);
  const events = await contract.queryFilter(filter, fromBlock);
  return events.map((e: any) => ({
    recipientHash: e.args[0],
    sender: e.args[1],
    pubKeys: e.args[2],
    ephemeralPubKey: e.args[3],
    plaintextPayload: e.args[4],
    blockNumber: e.blockNumber,
    transactionHash: e.transactionHash,
  }));
}

export async function scanHandshakeResponseEvents(
  contract: ethers.Contract,
  fromBlock: number
) {
  const filter = contract.filters.HandshakeResponse();
  const events = await contract.queryFilter(filter, fromBlock);
  return events.map((e: any) => ({
    inResponseTo: e.args[0],
    responder: e.args[1],
    responderEphemeralR: e.args[2],
    ciphertext: e.args[3],
    blockNumber: e.blockNumber,
    transactionHash: e.transactionHash,
  }));
}

export async function scanMessageEvents(
  contract: ethers.Contract,
  senderAddress: string | undefined,
  topicFilter: string | undefined,
  fromBlock: number
) {
  const filter = contract.filters.MessageSent(
    senderAddress ?? null,
    null,
    null,
    topicFilter ?? null
  );
  const events = await contract.queryFilter(filter, fromBlock);
  return events.map((e: any) => ({
    sender: e.args[0],
    ciphertext: e.args[1],
    timestamp: Number(e.args[2]),
    topic: e.args[3],
    nonce: e.args[4],
    blockNumber: e.blockNumber,
    transactionHash: e.transactionHash,
  }));
}
