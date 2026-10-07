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

## Deploy

`app.json` supports one-click deploy to Heroku:

[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/GainRangerHeffe/bloksi)

## Status

Built in 2025. Not actively maintained.

## License

MIT
