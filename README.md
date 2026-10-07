# Bloksi

Multi-chain crypto portfolio tracker and trading journal. Bloksi syncs a wallet's token trades and liquidity positions across Ethereum, BNB Smart Chain, Base and PulseChain, and reports profit and loss.

This repo is the backend API. The X Optimizer service that ran alongside it on the same site lives in [x-optimizer-backend](https://github.com/GainRangerHeffe/x-optimizer-backend).

## Features

- Wallet sync across four chains
- Per-token profit and loss
- Liquidity position tracking
- Portfolio analytics
- Automatic transaction import

## Stack

Node.js 18, Express, MongoDB (Mongoose) and ethers v6, with Helmet, compression and rate limiting.

## API

| Method | Route | Purpose |
|---|---|---|
| GET | `/api/health` | Health check |
| GET | `/api/users/:address` | User profile for a wallet |
| GET | `/api/tokens/:address/:chain` | Token positions on one chain |
| GET | `/api/tokens/:address/:chain/:tokenId` | One token position |
| GET | `/api/liquidity/:address` | Liquidity positions |
| GET | `/api/liquidity/:address/:positionId` | One liquidity position |
| GET | `/api/analytics/:address` | Portfolio analytics |
| POST | `/api/sync` | Sync a wallet's on-chain activity |

## How it works

`POST /api/sync` scans a wallet's ERC-20 `Transfer` logs on each chain (the last 10,000 blocks on a first sync, then from where it left off), stores each transfer, and recalculates per-token totals. Incoming transfers are recorded as buys and outgoing ones as sells.

## Known limitations

- **No price oracle.** The fields named `priceUSD` and `valueUSD` hold values in the chain's native coin (ETH, BNB or PLS), worked out from the native coin sent with the transaction. Sells and token-to-token swaps send no native coin, so they are valued at zero, and realized PnL is only a rough guide.
- **Unrealized PnL is always 0.** It needs a current market price, which this service does not have.
- **Win rate is always 0.** Per-transaction PnL is never calculated.
- **Plain transfers count as trades.** Moving tokens between your own wallets shows up as a sell and a buy.
- **Liquidity routes are read-only.** Nothing in the sync writes liquidity positions yet.
- **Anyone can sync or read any address.** There is no authentication; the sync route is rate limited to 10 requests per 15 minutes per IP.

## Run locally

```bash
npm install
npm run dev
```

Create a `.env` file first:

| Variable | Required | Purpose |
|---|---|---|
| `MONGODB_URI` | yes | MongoDB connection string |
| `FRONTEND_URL` | yes in production | Allowed CORS origin |
| `ETHEREUM_RPC`, `BSC_RPC`, `BASE_RPC`, `PULSECHAIN_RPC` | no | Custom RPC endpoints; public ones are used by default |
| `PORT` | no | Defaults to 3000 |

Never commit the `.env` file or a real connection string.

## Tests

```bash
npm test
```

The tests cover input validation on every route and the decoding of token names and symbols. They need no database or network.

## Upgrading an existing database

Transactions are now unique per wallet, chain, hash and log index, so that both sides of a swap are stored. A database created by an earlier version still has a unique index on `hash` alone; drop it once with `db.transactions.dropIndex("hash_1")`.

## Deploy

`app.json` supports one-click deploy to Heroku:

[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/GainRangerHeffe/bloksi)

## Status

Built in 2025. Not actively maintained.

## License

MIT
