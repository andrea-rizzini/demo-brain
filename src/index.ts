import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) (globalThis as any).crypto = webcrypto;

import dotenv from 'dotenv';
import Fastify from 'fastify';
import { randomBytes } from 'node:crypto';
import {
  createPublicClient,
  createWalletClient,
  formatEther,
  hashMessage,
  http,
  parseEther,
} from 'viem';
import { sepolia } from 'viem/chains';
import { mnemonicToAccount } from 'viem/accounts';
import { ethers } from 'ethers';
import {
  getCreationBlock,
  decryptAndExtractHandshakeKeys,
  decodeUnifiedPubKeys,
} from '@verbeth/sdk';
import {
  initVerbeth,
  savePendingHandshake,
  getPendingHandshake,
  deletePendingHandshake,
  saveContactInfo,
  getContactInfo,
  scanHandshakeEvents,
  scanHandshakeResponseEvents,
  scanMessageEvents,
  type VerbethInstance,
} from './verbeth.js';

dotenv.config();

async function main() {
  const mnemonic = process.env.MNEMONIC;

  if (!mnemonic) {
    console.error('MNEMONIC environment variable is not set');
    process.exit(1);
  }

  // Derive the agent's signing account from the TEE-provided mnemonic
  let account;
  try {
    account = mnemonicToAccount(mnemonic);
  } catch (error) {
    console.error('Error deriving signing account:', error);
    process.exit(1);
  }

  // Create viem clients for reading and writing to Sepolia
  const publicClient = createPublicClient({
    chain: sepolia,
    transport: http(process.env.RPC_URL || 'https://rpc.sepolia.org'),
  });

  const walletClient = createWalletClient({
    account,
    chain: sepolia,
    transport: http(process.env.RPC_URL || 'https://rpc.sepolia.org'),
  });

  console.log(`Agent wallet address: ${account.address}`);

  const server = Fastify({ logger: true });

  // GET /wallet — Show agent's address and ETH balance
  server.get('/wallet', async () => {
    const balance = await publicClient.getBalance({ address: account.address });
    return {
      address: account.address,
      balance: formatEther(balance),
      balanceWei: balance.toString(),
      chain: 'sepolia',
    };
  });

  // POST /send — Send ETH to a recipient address
  server.post<{
    Body: { to: string; amount: string };
  }>('/send', async (request, reply) => {
    const { to, amount } = request.body;

    if (!to || !amount) {
      return reply.status(400).send({ error: 'Missing "to" address or "amount" in ETH' });
    }

    try {
      const hash = await walletClient.sendTransaction({
        to: to as `0x${string}`,
        value: parseEther(amount),
      });

      const receipt = await publicClient.waitForTransactionReceipt({ hash });

      return {
        success: true,
        txHash: hash,
        from: account.address,
        to,
        amount,
        blockNumber: receipt.blockNumber.toString(),
        explorerUrl: `https://sepolia.etherscan.io/tx/${hash}`,
      };
    } catch (error: any) {
      return reply.status(500).send({
        error: 'Transaction failed',
        message: error.message,
      });
    }
  });

  // GET /random — Attested randomness beacon (original template)
  server.get('/random', async () => {
    const entropy = randomBytes(32);
    const randomNumber = `0x${entropy.toString('hex')}`;
    const randomNumberDecimal = BigInt(randomNumber).toString();
    const timestamp = new Date().toISOString();
    const message = `RandomnessBeacon|${randomNumber}|${timestamp}`;
    const messageHash = hashMessage(message);
    const signature = await account.signMessage({ message });

    return {
      randomNumber,
      randomNumberDecimal,
      timestamp,
      message,
      messageHash,
      signature,
      signer: account.address,
    };
  });

  // GET /health — Simple health check
  server.get('/health', async () => {
    return { status: 'ok', agent: account.address };
  });

  // ─── Verbeth Messaging ───────────────────────────────────────────────
  let verbeth: VerbethInstance | null = null;
  const verbethRpcUrl =
    process.env.VERBETH_RPC_URL ||
    process.env.RPC_URL ||
    'https://rpc.sepolia.org';

  try {
    verbeth = await initVerbeth(mnemonic, verbethRpcUrl);
  } catch (error: any) {
    console.error('Verbeth init failed (messaging disabled):', error.message);
  }

  // GET /verbeth/status
  server.get('/verbeth/status', async (_req, reply) => {
    if (!verbeth) return reply.status(503).send({ error: 'Verbeth not initialized' });
    const sessions = verbeth.sessionStore.getAll();
    return {
      address: verbeth.address,
      signingPubKey: Buffer.from(
        verbeth.client.identityKeyPairInstance.signingPublicKey
      ).toString('hex'),
      identityPubKey: Buffer.from(
        verbeth.client.identityKeyPairInstance.publicKey
      ).toString('hex'),
      sessionCount: sessions.length,
    };
  });

  // GET /verbeth/sessions
  server.get('/verbeth/sessions', async (_req, reply) => {
    if (!verbeth) return reply.status(503).send({ error: 'Verbeth not initialized' });
    const sessions = verbeth.sessionStore.getAll();
    return sessions.map((s) => ({
      conversationId: s.conversationId,
      contactAddress: s.contactAddress,
      topicEpoch: s.topicEpoch,
      sendingMsgNumber: s.sendingMsgNumber,
      receivingMsgNumber: s.receivingMsgNumber,
      createdAt: s.createdAt,
    }));
  });

  // POST /verbeth/handshake/initiate — initiate handshake
  server.post<{ Body: { to: string; message: string } }>(
    '/verbeth/handshake/initiate',
    async (request, reply) => {
      if (!verbeth) return reply.status(503).send({ error: 'Verbeth not initialized' });
      const { to, message } = request.body;
      if (!to || !message) {
        return reply.status(400).send({ error: 'Missing "to" or "message"' });
      }
      try {
        const { tx, ephemeralKeyPair, kemKeyPair } =
          await verbeth.client.sendHandshake(to, message);
        const receipt = await tx.wait();
        savePendingHandshake(to, ephemeralKeyPair.secretKey, kemKeyPair.secretKey);
        return {
          success: true,
          txHash: receipt.hash,
          to,
          message,
          note: 'Handshake sent. Waiting for recipient to accept.',
        };
      } catch (error: any) {
        return reply.status(500).send({ error: 'Handshake failed', message: error.message });
      }
    }
  );

  // GET /verbeth/handshake/incoming — list pending incoming handshakes
  server.get<{ Querystring: { fromBlock?: string } }>(
    '/verbeth/handshake/incoming',
    async (request, reply) => {
      if (!verbeth) return reply.status(503).send({ error: 'Verbeth not initialized' });
      const fromBlock = request.query.fromBlock
        ? Number(request.query.fromBlock)
        : getCreationBlock(verbeth.chainId);

      try {
        const events = await scanHandshakeEvents(
          verbeth.contract,
          verbeth.address,
          fromBlock
        );

        return {
          handshakes: events.map((e: any) => ({
            from: e.sender,
            blockNumber: e.blockNumber,
            txHash: e.transactionHash,
          })),
        };
      } catch (error: any) {
        return reply
          .status(500)
          .send({ error: 'Scan failed', message: error.message });
      }
    }
  );

  // POST /verbeth/handshake/accept — accept an incoming handshake
  server.post<{ Body: { from: string; fromBlock?: number } }>(
    '/verbeth/handshake/accept',
    async (request, reply) => {
      if (!verbeth) return reply.status(503).send({ error: 'Verbeth not initialized' });
      const { from, fromBlock } = request.body;
      if (!from) return reply.status(400).send({ error: 'Missing "from" address' });

      try {
        const startBlock = fromBlock ?? getCreationBlock(verbeth.chainId);
        const events = await scanHandshakeEvents(
          verbeth.contract,
          verbeth.address,
          startBlock
        );

        const hsEvent = events.find(
          (e: any) => e.sender.toLowerCase() === from.toLowerCase()
        );
        if (!hsEvent) {
          return reply
            .status(404)
            .send({ error: `No handshake found from ${from}` });
        }

        const initiatorEphemeralPubKey = ethers.getBytes(hsEvent.ephemeralPubKey);

        // Extract initiator's signing key from the handshake event's pubKeys field
        const pubKeysBytes = ethers.getBytes(hsEvent.pubKeys);
        const decoded = decodeUnifiedPubKeys(pubKeysBytes);
        if (decoded) {
          saveContactInfo(from, {
            signingPubKey: decoded.signingPubKey,
            identityPubKey: decoded.identityPubKey,
          });
        }

        const result = await verbeth.client.acceptHandshake(
          initiatorEphemeralPubKey,
          'Accepted'
        );
        const receipt = await result.tx.wait();

        const session = verbeth.client.createResponderSession({
          contactAddress: from,
          responderEphemeralSecret: result.responderEphemeralSecret,
          responderEphemeralPublic: result.responderEphemeralPublic,
          initiatorEphemeralPubKey,
          salt: result.salt,
          kemSharedSecret: result.kemSharedSecret,
        });
        await verbeth.sessionStore.save(session);

        return {
          success: true,
          txHash: receipt.hash,
          conversationId: session.conversationId,
          contactAddress: from,
        };
      } catch (error: any) {
        return reply
          .status(500)
          .send({ error: 'Accept handshake failed', message: error.message });
      }
    }
  );

  // POST /verbeth/handshake/complete — complete handshake as initiator
  server.post<{ Body: { from: string; fromBlock?: number } }>(
    '/verbeth/handshake/complete',
    async (request, reply) => {
      if (!verbeth) return reply.status(503).send({ error: 'Verbeth not initialized' });
      const { from, fromBlock } = request.body;
      if (!from) return reply.status(400).send({ error: 'Missing "from" address' });

      const pending = getPendingHandshake(from);
      if (!pending) {
        return reply.status(404).send({
          error: `No pending handshake secrets for ${from}. Did you initiate a handshake first?`,
        });
      }

      try {
        const startBlock = fromBlock ?? getCreationBlock(verbeth.chainId);
        const hsrEvents = await scanHandshakeResponseEvents(
          verbeth.contract,
          startBlock
        );

        // Find HSR events from the target responder and try to decrypt each
        const candidateEvents = hsrEvents.filter(
          (e: any) => e.responder.toLowerCase() === from.toLowerCase()
        );

        if (candidateEvents.length === 0) {
          return reply
            .status(404)
            .send({ error: `No handshake response found from ${from}` });
        }

        let matchedEvent: any = null;
        let extractedKeys: {
          identityPubKey: Uint8Array;
          signingPubKey: Uint8Array;
          ephemeralPubKey: Uint8Array;
          kemCiphertext?: Uint8Array;
          note?: string;
        } | null = null;

        for (const evt of candidateEvents) {
          const ciphertextStr =
            typeof evt.ciphertext === 'string'
              ? evt.ciphertext
              : ethers.hexlify(evt.ciphertext);

          const keys = decryptAndExtractHandshakeKeys(
            ciphertextStr,
            pending.ephemeralSecret
          );
          if (keys) {
            matchedEvent = evt;
            extractedKeys = keys;
            break;
          }
        }

        if (!matchedEvent || !extractedKeys) {
          return reply
            .status(404)
            .send({ error: `Could not decrypt any HSR from ${from}` });
        }

        // Store the responder's signing key for message decryption
        saveContactInfo(from, {
          signingPubKey: extractedKeys.signingPubKey,
          identityPubKey: extractedKeys.identityPubKey,
        });

        // Use the REAL ephemeral pubkey and KEM ciphertext from inside the encrypted payload
        const session = verbeth.client.createInitiatorSessionFromHsr({
          contactAddress: from,
          myEphemeralSecret: pending.ephemeralSecret,
          myKemSecret: pending.kemSecret,
          hsrEvent: {
            inResponseToTag: matchedEvent.inResponseTo as `0x${string}`,
            responderEphemeralPubKey: extractedKeys.ephemeralPubKey,
            kemCiphertext: extractedKeys.kemCiphertext,
          },
        });
        await verbeth.sessionStore.save(session);
        deletePendingHandshake(from);

        return {
          success: true,
          conversationId: session.conversationId,
          contactAddress: from,
        };
      } catch (error: any) {
        return reply
          .status(500)
          .send({ error: 'Complete handshake failed', message: error.message });
      }
    }
  );

  // POST /verbeth/send — send encrypted message
  server.post<{ Body: { to: string; message: string } }>(
    '/verbeth/send',
    async (request, reply) => {
      if (!verbeth) return reply.status(503).send({ error: 'Verbeth not initialized' });
      const { to, message } = request.body;
      if (!to || !message) {
        return reply.status(400).send({ error: 'Missing "to" or "message"' });
      }

      // Find session by contact address
      const sessions = verbeth.sessionStore.getAll();
      const session = sessions.find(
        (s) => s.contactAddress.toLowerCase() === to.toLowerCase()
      );
      if (!session) {
        return reply.status(404).send({
          error: `No session with ${to}. Complete a handshake first.`,
        });
      }

      try {
        const result = await verbeth.client.sendMessage(
          session.conversationId,
          message
        );
        return {
          success: true,
          txHash: result.txHash,
          topic: result.topic,
          messageNumber: result.messageNumber,
          conversationId: session.conversationId,
        };
      } catch (error: any) {
        return reply
          .status(500)
          .send({ error: 'Send message failed', message: error.message });
      }
    }
  );

  // GET /verbeth/messages — scan and decrypt incoming messages
  server.get<{ Querystring: { from?: string; fromBlock?: string } }>(
    '/verbeth/messages',
    async (request, reply) => {
      if (!verbeth) return reply.status(503).send({ error: 'Verbeth not initialized' });
      const { from, fromBlock: fromBlockStr } = request.query;
      const fromBlock = fromBlockStr ? Number(fromBlockStr) : getCreationBlock(verbeth.chainId);

      try {
        // Scan for messages on all inbound topics from our sessions
        const sessions = verbeth.sessionStore.getAll();
        const relevantSessions = from
          ? sessions.filter(
              (s) => s.contactAddress.toLowerCase() === from.toLowerCase()
            )
          : sessions;

        const decryptedMessages: any[] = [];

        for (const session of relevantSessions) {
          // Scan for messages on the current inbound topic
          const topics = [
            session.currentTopicInbound,
            session.nextTopicInbound,
            session.previousTopicInbound,
          ].filter(Boolean) as string[];

          for (const topic of topics) {
            const events = await scanMessageEvents(
              verbeth.contract,
              session.contactAddress,
              topic,
              fromBlock
            );

            // Get the contact's signing key for signature verification
            const contact = getContactInfo(session.contactAddress);
            if (!contact) {
              // Skip — we don't have this contact's signing key yet
              continue;
            }

            for (const evt of events) {
              try {
                const payload = ethers.getBytes(evt.ciphertext);
                const decrypted = await verbeth.client.decryptMessage(
                  evt.topic,
                  payload,
                  contact.signingPubKey,
                  false
                );
                if (decrypted) {
                  decryptedMessages.push({
                    from: evt.sender,
                    plaintext: decrypted.plaintext,
                    topic: evt.topic,
                    timestamp: evt.timestamp,
                    blockNumber: evt.blockNumber,
                    txHash: evt.transactionHash,
                  });
                }
              } catch {
                // Skip messages we can't decrypt
              }
            }
          }
        }

        return { messages: decryptedMessages, scannedFromBlock: fromBlock };
      } catch (error: any) {
        return reply
          .status(500)
          .send({ error: 'Message scan failed', message: error.message });
      }
    }
  );

  const port = Number(process.env.PORT ?? 8080);
  try {
    await server.listen({ port, host: '0.0.0.0' });
    console.log(`Agent running on port ${port}`);
  } catch (error) {
    server.log.error(error);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error('Fatal error starting server:', error);
  process.exit(1);
});
