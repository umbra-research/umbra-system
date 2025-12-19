# Umbra System (Backend)

## Overview

`umbra-system` is the Backend-as-a-Service (BaaS) layer for the Umbra protocol. It acts as a facilitator for light clients (like web browsers) that cannot easily perform heavy cryptographic scanning or manage complex private key operations securely.

## Features

-   **API Layer**: Exposes REST endpoints (`/api/send`, `/api/inbox`, `/api/claim`) for the frontend.
-   **Transaction Registry**: Indexes sent transfers to provide a fast "Inbox" experience for users without requiring full-chain scanning.
-   **Shadow Identity Manager (Demo)**: In the current demo environment, this service manages "Shadow Identities" for recipients. This allows the backend to perform the "Sweep" (Claim) operation on behalf of the user, bypassing limitations in browser wallets regarding signing for non-standard derived addresses.

## Architecture

run `cargo run` to start the server.

-   **Framework**: Rust `axum` (Web Server).
-   **State**: In-memory `Mutex` for the Transaction Registry and Shadow Identities (resets on restart).
-   **Encryption**: Uses `umbra-core` for all key logic.

## API Endpoints

### `POST /api/send`
Creates an unsigned transaction for the user to sign.
-   **Input**: `{ payer, recipient, amount, token }`
-   **Output**: `{ transaction: <base64_tx>, status: "created" }`

### `GET /api/inbox`
Retrieves a list of claimable transfers for a recipient.
-   **Query**: `?recipient=<pubkey>`
-   **Output**: `[ { id, amount, status, ... } ]`

### `POST /api/claim`
Triggers the backend to sweep funds from the stealth address to the recipient's main wallet using the Shadow Identity.
-   **Input**: `{ recipient: <pubkey> }`
-   **Output**: `{ status: "success", signatures: [...] }`
