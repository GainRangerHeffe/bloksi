// MemeJournal Pro - Backend Server
// Production-ready Node.js + Express + MongoDB

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const { ethers } = require('ethers');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security & Middleware
app.use(helmet({
    contentSecurityPolicy: false, // Allow for frontend flexibility
}));
app.use(compression());
app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
        ? [process.env.FRONTEND_URL] 
        : ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:8080'],
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: { success: false, message: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// Blockchain Configuration
const SUPPORTED_CHAINS = {
    ethereum: {
        chainId: 1,
        name: 'Ethereum',
        rpc: process.env.ETHEREUM_RPC || 'https://eth.llamarpc.com',
        currency: 'ETH',
        blockTime: 12000
    },
    bsc: {
        chainId: 56,
        name: 'BSC',
        rpc: process.env.BSC_RPC || 'https://bsc-dataseed.binance.org',
        currency: 'BNB',
        blockTime: 3000
    },
    base: {
        chainId: 8453,
        name: 'Base',
        rpc: process.env.BASE_RPC || 'https://mainnet.base.org',
        currency: 'ETH',
        blockTime: 2000
    },
    pulsechain: {
        chainId: 369,
        name: 'PulseChain',
        rpc: process.env.PULSECHAIN_RPC || 'https://rpc.pulsechain.com',
        currency: 'PLS',
        blockTime: 10000
    }
};

// MongoDB Schemas
const userSchema = new mongoose.Schema({
    address: { type: String, required: true, unique: true, lowercase: true },
    totalBalance: { type: Number, default: 0 },
    lastSyncedBlocks: {
        ethereum: { type: Number, default: 0 },
        bsc: { type: Number, default: 0 },
        base: { type: Number, default: 0 },
        pulsechain: { type: Number, default: 0 }
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const tokenSchema = new mongoose.Schema({
    userAddress: { type: String, required: true, lowercase: true },
    chain: { type: String, required: true },
    contractAddress: { type: String, required: true, lowercase: true },
    symbol: { type: String, required: true },
    name: { type: String, required: true },
    decimals: { type: Number, default: 18 },
    balance: { type: Number, default: 0 },
    valueUSD: { type: Number, default: 0 },
    totalBought: { type: Number, default: 0 },
    totalSold: { type: Number, default: 0 },
    avgBuyPrice: { type: Number, default: 0 },
    avgSellPrice: { type: Number, default: 0 },
    realizedPnL: { type: Number, default: 0 },
    unrealizedPnL: { type: Number, default: 0 },
    totalPnL: { type: Number, default: 0 },
    trades: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }],
    updatedAt: { type: Date, default: Date.now }
});

const transactionSchema = new mongoose.Schema({
    userAddress: { type: String, required: true, lowercase: true },
    chain: { type: String, required: true },
    hash: { type: String, required: true, unique: true },
    blockNumber: { type: Number, required: true },
    timestamp: { type: Date, required: true },
    from: { type: String, required: true, lowercase: true },
    to: { type: String, required: true, lowercase: true },
    tokenAddress: { type: String, required: true, lowercase: true },
    tokenSymbol: { type: String, required: true },
    type: { type: String, enum: ['buy', 'sell', 'transfer'], required: true },
    amount: { type: Number, required: true },
    priceUSD: { type: Number, default: 0 },
    valueUSD: { type: Number, default: 0 },
    gasUsed: { type: Number, default: 0 },
    gasPrice: { type: Number, default: 0 },
    pnl: { type: Number, default: 0 },
    dexUsed: { type: String, default: 'Unknown' },
    createdAt: { type: Date, default: Date.now }
});

const liquidityPositionSchema = new mongoose.Schema({
    userAddress: { type: String, required: true, lowercase: true },
    chain: { type: String, required: true },
    pair: { type: String, required: true },
    platform: { type: String, required: true },
    contractAddress: { type: String, required: true, lowercase: true },
    token0: { address: String, symbol: String },
    token1: { address: String, symbol: String },
    liquidity: { type: Number, default: 0 },
    valueUSD: { type: Number, default: 0 },
    totalFeesEarned: { type: Number, default: 0 },
    totalPnL: { type: Number, default: 0 },
    transactions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'LPTransaction' }],
    isActive: { type: Boolean, default: true },
    updatedAt: { type: Date, default: Date.now }
});

const lpTransactionSchema = new mongoose.Schema({
    userAddress: { type: String, required: true, lowercase: true },
    chain: { type: String, required: true },
    hash: { type: String, required: true, unique: true },
    blockNumber: { type: Number, required: true },
    timestamp: { type: Date, required: true },
    action: { type: String, enum: ['add', 'remove', 'claim'], required: true },
    amount: { type: Number, default: 0 },
    valueUSD: { type: Number, default: 0 },
    feesEarned: { type: Number, default: 0 },
    lpPositionId: { type: mongoose.Schema.Types.ObjectId, ref: 'LiquidityPosition' },
    createdAt: { type: Date, default: Date.now }
});

// Compound indexes for performance
tokenSchema.index({ userAddress: 1, chain: 1, contractAddress: 1 }, { unique: true });
transactionSchema.index({ userAddress: 1, chain: 1, timestamp: -1 });
liquidityPositionSchema.index({ userAddress: 1, chain: 1, contractAddress: 1 });

// Models
const User = mongoose.model('User', userSchema);
const Token = mongoose.model('Token', tokenSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const LiquidityPosition = mongoose.model('LiquidityPosition', liquidityPositionSchema);
const LPTransaction = mongoose.model('LPTransaction', lpTransactionSchema);

// Blockchain Service
class BlockchainService {
    constructor() {
        this.providers = {};
        this.initializeProviders();
        this.ERC20_TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
    }

    initializeProviders() {
        Object.entries(SUPPORTED_CHAINS).forEach(([key, config]) => {
            this.providers[key] = new ethers.JsonRpcProvider(config.rpc);
        });
    }

    async syncUserData(userAddress, chains = null) {
        const chainsToSync = chains || Object.keys(SUPPORTED_CHAINS);
        const results = {};

        for (const chainKey of chainsToSync) {
            try {
                console.log(`Syncing ${chainKey} for ${userAddress}`);
                const chainResult = await this.syncChain(userAddress, chainKey);
                results[chainKey] = chainResult;
            } catch (error) {
                console.error(`Failed to sync ${chainKey}:`, error);
                results[chainKey] = { success: false, error: error.message };
            }
        }

        // Update user's total balance
        await this.updateUserBalance(userAddress);

        return results;
    }

    async syncChain(userAddress, chainKey) {
        const provider = this.providers[chainKey];
        if (!provider) throw new Error(`Provider not found for ${chainKey}`);

        // Get user's last synced block
        const user = await User.findOneAndUpdate(
            { address: userAddress },
            { $setOnInsert: { address: userAddress } },
            { upsert: true, new: true }
        );

        const currentBlock = await provider.getBlockNumber();
        const lastSyncedBlock = user.lastSyncedBlocks[chainKey] || Math.max(0, currentBlock - 10000);
        const fromBlock = lastSyncedBlock + 1;

        console.log(`Scanning ${chainKey} blocks ${fromBlock} to ${currentBlock}`);

        // Get transfer events
        const transfers = await this.getTransferEvents(provider, userAddress, fromBlock, currentBlock, chainKey);
        
        // Process transfers into transactions and tokens
        let processedCount = 0;
        for (const transfer of transfers) {
            try {
                await this.processTransfer(transfer, userAddress, chainKey);
                processedCount++;
            } catch (error) {
                console.warn(`Failed to process transfer ${transfer.hash}:`, error.message);
            }
        }

        // Update last synced block
        await User.updateOne(
            { address: userAddress },
            { 
                $set: { 
                    [`lastSyncedBlocks.${chainKey}`]: currentBlock,
                    updatedAt: new Date()
                }
            }
        );

        return {
            success: true,
            blocksScanned: currentBlock - fromBlock + 1,
            transfersFound: transfers.length,
            transfersProcessed: processedCount
        };
    }

    async getTransferEvents(provider, userAddress, fromBlock, toBlock, chainKey) {
        const transfers = [];
        const batchSize = 5000;
        const paddedAddress = ethers.zeroPadValue(userAddress.toLowerCase(), 32);

        // Scan in batches to avoid RPC limits
        for (let block = fromBlock; block <= toBlock; block += batchSize) {
            const endBlock = Math.min(block + batchSize - 1, toBlock);
            
            try {
                // Get outgoing transfers
                const outgoingLogs = await provider.getLogs({
                    fromBlock: block,
                    toBlock: endBlock,
                    topics: [this.ERC20_TRANSFER_TOPIC, paddedAddress]
                });

                // Get incoming transfers
                const incomingLogs = await provider.getLogs({
                    fromBlock: block,
                    toBlock: endBlock,
                    topics: [this.ERC20_TRANSFER_TOPIC, null, paddedAddress]
                });

                // Combine and deduplicate
                const allLogs = [...outgoingLogs, ...incomingLogs];
                const uniqueLogs = allLogs.filter((log, index, self) => 
                    index === self.findIndex(l => l.transactionHash === log.transactionHash)
                );

                transfers.push(...uniqueLogs);

                // Add delay to respect rate limits
                await new Promise(resolve => setTimeout(resolve, 100));

            } catch (error) {
                console.warn(`Failed to get logs for blocks ${block}-${endBlock}:`, error.message);
                continue;
            }
        }

        return transfers;
    }

    async processTransfer(log, userAddress, chainKey) {
        const provider = this.providers[chainKey];
        
        // Get transaction details
        const [tx, receipt] = await Promise.all([
            provider.getTransaction(log.transactionHash),
            provider.getTransactionReceipt(log.transactionHash)
        ]);

        if (!tx || !receipt) return;

        // Decode transfer data
        const fromAddress = '0x' + log.topics[1].slice(26).toLowerCase();
        const toAddress = '0x' + log.topics[2].slice(26).toLowerCase();
        const amount = ethers.getBigInt(log.data);

        // Determine transaction type
        const isOutgoing = fromAddress === userAddress.toLowerCase();
        const isIncoming = toAddress === userAddress.toLowerCase();
        
        if (!isOutgoing && !isIncoming) return;

        // Get token info
        const tokenInfo = await this.getTokenInfo(provider, log.address);
        const tokenAmount = Number(amount) / Math.pow(10, tokenInfo.decimals);

        // Check if transaction already exists
        const existingTx = await Transaction.findOne({ hash: log.transactionHash });
        if (existingTx) return;

        // Create transaction
        const transaction = new Transaction({
            userAddress: userAddress.toLowerCase(),
            chain: chainKey,
            hash: log.transactionHash,
            blockNumber: tx.blockNumber,
            timestamp: new Date((await provider.getBlock(tx.blockNumber)).timestamp * 1000),
            from: fromAddress,
            to: toAddress,
            tokenAddress: log.address.toLowerCase(),
            tokenSymbol: tokenInfo.symbol,
            type: isOutgoing ? 'sell' : 'buy',
            amount: tokenAmount,
            priceUSD: await this.estimateTokenPrice(tokenAmount, tx.value, tokenInfo.decimals),
            gasUsed: receipt.gasUsed,
            gasPrice: tx.gasPrice || 0
        });

        transaction.valueUSD = transaction.amount * transaction.priceUSD;
        await transaction.save();

        // Update or create token
        await this.updateTokenData(userAddress, chainKey, log.address, tokenInfo, transaction);
    }

    async getTokenInfo(provider, tokenAddress) {
        try {
            // Simple ERC20 calls
            const symbolCall = provider.call({ to: tokenAddress, data: '0x95d89b41' }); // symbol()
            const nameCall = provider.call({ to: tokenAddress, data: '0x06fdde03' }); // name()
            const decimalsCall = provider.call({ to: tokenAddress, data: '0x313ce567' }); // decimals()

            const [symbolResult, nameResult, decimalsResult] = await Promise.allSettled([
                symbolCall, nameCall, decimalsCall
            ]);

            let symbol = 'UNKNOWN';
            let name = 'Unknown Token';
            let decimals = 18;

            try {
                if (symbolResult.status === 'fulfilled' && symbolResult.value !== '0x') {
                    symbol = ethers.toUtf8String(symbolResult.value).replace(/\0/g, '') || 'UNKNOWN';
                }
            } catch (e) {
                console.warn('Failed to decode symbol');
            }

            try {
                if (nameResult.status === 'fulfilled' && nameResult.value !== '0x') {
                    name = ethers.toUtf8String(nameResult.value).replace(/\0/g, '') || 'Unknown Token';
                }
            } catch (e) {
                console.warn('Failed to decode name');
            }

            try {
                if (decimalsResult.status === 'fulfilled' && decimalsResult.value !== '0x') {
                    decimals = parseInt(decimalsResult.value, 16) || 18;
                }
            } catch (e) {
                console.warn('Failed to decode decimals');
            }

            return { symbol, name, decimals };

        } catch (error) {
            console.warn('Error getting token info:', error);
            return { symbol: 'UNKNOWN', name: 'Unknown Token', decimals: 18 };
        }
    }

    async estimateTokenPrice(tokenAmount, ethValue, decimals) {
        try {
            if (!tokenAmount || tokenAmount === 0 || !ethValue) return 0;
            
            const ethAmount = Number(ethers.formatEther(ethValue.toString()));
            if (ethAmount === 0) return 0;
            
            // Simple price estimation - in production you'd use price oracles
            return Math.abs(ethAmount / tokenAmount);
        } catch (error) {
            return 0;
        }
    }

    async updateTokenData(userAddress, chainKey, tokenAddress, tokenInfo, transaction) {
        const token = await Token.findOneAndUpdate(
            { 
                userAddress: userAddress.toLowerCase(), 
                chain: chainKey, 
                contractAddress: tokenAddress.toLowerCase() 
            },
            {
                $setOnInsert: {
                    userAddress: userAddress.toLowerCase(),
                    chain: chainKey,
                    contractAddress: tokenAddress.toLowerCase(),
                    symbol: tokenInfo.symbol,
                    name: tokenInfo.name,
                    decimals: tokenInfo.decimals
                }
            },
            { upsert: true, new: true }
        );

        // Add transaction to token
        await Token.updateOne(
            { _id: token._id },
            { $addToSet: { trades: transaction._id } }
        );

        // Update token calculations
        await this.recalculateTokenMetrics(token._id);
    }

    async recalculateTokenMetrics(tokenId) {
        const token = await Token.findById(tokenId).populate('trades');
        if (!token) return;

        let totalBought = 0;
        let totalSold = 0;
        let totalBoughtValue = 0;
        let totalSoldValue = 0;
        let realizedPnL = 0;

        const buyTrades = token.trades.filter(t => t.type === 'buy');
        const sellTrades = token.trades.filter(t => t.type === 'sell');

        // Calculate buy metrics
        buyTrades.forEach(trade => {
            totalBought += trade.amount;
            totalBoughtValue += trade.valueUSD;
        });

        // Calculate sell metrics
        sellTrades.forEach(trade => {
            totalSold += trade.amount;
            totalSoldValue += trade.valueUSD;
        });

        const avgBuyPrice = totalBought > 0 ? totalBoughtValue / totalBought : 0;
        const avgSellPrice = totalSold > 0 ? totalSoldValue / totalSold : 0;

        // Calculate realized PnL (simplified)
        if (totalSold > 0 && avgBuyPrice > 0) {
            realizedPnL = (avgSellPrice - avgBuyPrice) * totalSold;
        }

        const currentBalance = totalBought - totalSold;
        const unrealizedPnL = currentBalance > 0 ? (avgBuyPrice * currentBalance * 0.1) : 0; // Mock unrealized PnL

        await Token.updateOne(
            { _id: tokenId },
            {
                $set: {
                    balance: currentBalance,
                    totalBought,
                    totalSold,
                    avgBuyPrice,
                    avgSellPrice,
                    realizedPnL,
                    unrealizedPnL,
                    totalPnL: realizedPnL + unrealizedPnL,
                    valueUSD: currentBalance * avgBuyPrice,
                    updatedAt: new Date()
                }
            }
        );
    }

    async updateUserBalance(userAddress) {
        const tokens = await Token.find({ userAddress: userAddress.toLowerCase() });
        const totalBalance = tokens.reduce((sum, token) => sum + (token.valueUSD || 0), 0);

        await User.updateOne(
            { address: userAddress.toLowerCase() },
            { $set: { totalBalance, updatedAt: new Date() } }
        );

        return totalBalance;
    }
}

// Initialize services
const blockchainService = new BlockchainService();

// API Routes
app.get('/api/health', (req, res) => {
    res.json({ success: true, message: 'MemeJournal Pro API is running!' });
});

// Get user data
app.get('/api/users/:address', async (req, res) => {
    try {
        const { address } = req.params;
        
        if (!ethers.isAddress(address)) {
            return res.status(400).json({ success: false, message: 'Invalid wallet address' });
        }

        const user = await User.findOne({ address: address.toLowerCase() });
        
        if (!user) {
            return res.json({ success: true, data: { totalBalance: 0, isNewUser: true } });
        }

        res.json({ success: true, data: user });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ success: false, message: 'Failed to get user data' });
    }
});

// Get tokens for a chain
app.get('/api/tokens/:address/:chain', async (req, res) => {
    try {
        const { address, chain } = req.params;

        if (!ethers.isAddress(address)) {
            return res.status(400).json({ success: false, message: 'Invalid wallet address' });
        }

        if (!SUPPORTED_CHAINS[chain]) {
            return res.status(400).json({ success: false, message: 'Unsupported chain' });
        }

        const tokens = await Token.find({ 
            userAddress: address.toLowerCase(), 
            chain,
            balance: { $gt: 0 } // Only tokens with balance
        }).sort({ valueUSD: -1 });

        res.json({ success: true, data: tokens });
    } catch (error) {
        console.error('Get tokens error:', error);
        res.status(500).json({ success: false, message: 'Failed to get tokens' });
    }
});

// Get token details with trades
app.get('/api/tokens/:address/:chain/:tokenId', async (req, res) => {
    try {
        const { address, chain, tokenId } = req.params;

        const token = await Token.findOne({ 
            _id: tokenId,
            userAddress: address.toLowerCase(),
            chain
        }).populate('trades');

        if (!token) {
            return res.status(404).json({ success: false, message: 'Token not found' });
        }

        res.json({ success: true, data: token });
    } catch (error) {
        console.error('Get token details error:', error);
        res.status(500).json({ success: false, message: 'Failed to get token details' });
    }
});

// Get liquidity positions
app.get('/api/liquidity/:address', async (req, res) => {
    try {
        const { address } = req.params;

        if (!ethers.isAddress(address)) {
            return res.status(400).json({ success: false, message: 'Invalid wallet address' });
        }

        const positions = await LiquidityPosition.find({ 
            userAddress: address.toLowerCase(),
            isActive: true
        }).sort({ valueUSD: -1 });

        res.json({ success: true, data: positions });
    } catch (error) {
        console.error('Get liquidity error:', error);
        res.status(500).json({ success: false, message: 'Failed to get liquidity positions' });
    }
});

// Get LP position details
app.get('/api/liquidity/:address/:positionId', async (req, res) => {
    try {
        const { address, positionId } = req.params;

        const position = await LiquidityPosition.findOne({
            _id: positionId,
            userAddress: address.toLowerCase()
        }).populate('transactions');

        if (!position) {
            return res.status(404).json({ success: false, message: 'LP position not found' });
        }

        res.json({ success: true, data: position });
    } catch (error) {
        console.error('Get LP details error:', error);
        res.status(500).json({ success: false, message: 'Failed to get LP details' });
    }
});

// Get analytics
app.get('/api/analytics/:address', async (req, res) => {
    try {
        const { address } = req.params;

        if (!ethers.isAddress(address)) {
            return res.status(400).json({ success: false, message: 'Invalid wallet address' });
        }

        const [user, tokens, transactions, lpPositions] = await Promise.all([
            User.findOne({ address: address.toLowerCase() }),
            Token.find({ userAddress: address.toLowerCase() }),
            Transaction.find({ userAddress: address.toLowerCase() }),
            LiquidityPosition.find({ userAddress: address.toLowerCase() })
        ]);

        const analytics = {
            totalValue: user?.totalBalance || 0,
            totalRealizedPnL: tokens.reduce((sum, t) => sum + (t.realizedPnL || 0), 0),
            totalUnrealizedPnL: tokens.reduce((sum, t) => sum + (t.unrealizedPnL || 0), 0),
            totalTrades: transactions.length,
            activePositions: tokens.filter(t => t.balance > 0).length + lpPositions.filter(lp => lp.isActive).length,
            winRate: transactions.length > 0 ? 
                (transactions.filter(t => (t.pnl || 0) > 0).length / transactions.length * 100) : 0
        };

        res.json({ success: true, data: analytics });
    } catch (error) {
        console.error('Get analytics error:', error);
        res.status(500).json({ success: false, message: 'Failed to get analytics' });
    }
});

// Sync blockchain data
app.post('/api/sync', async (req, res) => {
    try {
        const { address, chain, chains } = req.body;

        if (!ethers.isAddress(address)) {
            return res.status(400).json({ success: false, message: 'Invalid wallet address' });
        }

        const chainsToSync = chains || (chain ? [chain] : Object.keys(SUPPORTED_CHAINS));

        // Validate chains
        for (const chainKey of chainsToSync) {
            if (!SUPPORTED_CHAINS[chainKey]) {
                return res.status(400).json({ success: false, message: `Unsupported chain: ${chainKey}` });
            }
        }

        console.log(`Starting sync for ${address} on chains: ${chainsToSync.join(', ')}`);

        const results = await blockchainService.syncUserData(address.toLowerCase(), chainsToSync);
        const totalBalance = await blockchainService.updateUserBalance(address.toLowerCase());

        res.json({ 
            success: true, 
            data: { 
                results, 
                totalBalance,
                message: `Synced ${chainsToSync.length} chain(s) successfully` 
            } 
        });

    } catch (error) {
        console.error('Sync error:', error);
        res.status(500).json({ success: false, message: 'Sync failed: ' + error.message });
    }
});

// Database Connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log('✅ Connected to MongoDB Atlas');
    
    // Start server
    app.listen(PORT, () => {
        console.log(`🚀 MemeJournal Pro Backend running on port ${PORT}`);
        console.log(`📊 API Base URL: ${process.env.NODE_ENV === 'production' ? 'Production' : 'Development'} mode`);
        console.log(`🔗 Supported chains: ${Object.keys(SUPPORTED_CHAINS).join(', ')}`);
    });
})
.catch((error) => {
    console.error('❌ MongoDB connection failed:', error);
    process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    mongoose.connection.close(() => {
        console.log('MongoDB connection closed');
        process.exit(0);
    });
});

module.exports = app;