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
