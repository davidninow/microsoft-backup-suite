# OneDrive Auth Service

A hosted OAuth service for the OneDrive Backup Tool, enabling users to simply "Login with Microsoft" without setting up their own Azure app registration.

## Architecture

```
Desktop App  →  Auth Service (Cloudflare Workers)  →  Microsoft
     ↓                    ↓
Downloads files      Handles OAuth only
directly from        (tokens, no files)
Microsoft
```

**Privacy Guarantee:** Files NEVER touch the auth server - only OAuth tokens are handled.

## Features

- **Simple Login**: Users click "Login with Microsoft" → browser opens → done
- **PKCE Flow**: Secure OAuth 2.0 with S256 code challenge
- **Encrypted Storage**: Refresh tokens encrypted with AES-256-GCM
- **Auto-Expiring Sessions**: KV entries expire after 90 days
- **Hashed User IDs**: Microsoft user IDs are SHA-256 hashed before storage

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/auth/login` | POST | Start OAuth flow, returns Microsoft auth URL |
| `/auth/callback` | POST | Exchange auth code for tokens |
| `/auth/refresh` | POST | Refresh access token |
| `/auth/logout` | POST | Delete stored tokens |

## Setup

### Prerequisites

- [Node.js](https://nodejs.org/) 18+
- [Cloudflare account](https://dash.cloudflare.com/sign-up)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)

### 1. Create Microsoft App Registration

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** → **App registrations** → **New registration**
3. Configure:
   - Name: `OneDrive Backup Service`
   - Supported account types: **Personal Microsoft accounts only**
   - Redirect URI: `http://localhost:8400/callback` (Web)
4. After creation, note the **Application (client) ID**
5. Go to **Certificates & secrets** → **New client secret**
   - Copy the secret value immediately (you won't see it again)
6. Go to **API permissions** → **Add a permission** → **Microsoft Graph** → **Delegated permissions**
   - Add: `Files.Read.All`, `offline_access`, `openid`, `profile`
7. Click **Grant admin consent** (if available)

### 2. Create Cloudflare KV Namespace

```bash
# Login to Cloudflare
npx wrangler login

# Create KV namespace
npx wrangler kv:namespace create "AUTH_TOKENS"
```

Copy the namespace ID from the output.

### 3. Configure Secrets

```bash
# Set Microsoft Client ID
npx wrangler secret put MICROSOFT_CLIENT_ID
# Enter your Application (client) ID

# Set Microsoft Client Secret
npx wrangler secret put MICROSOFT_CLIENT_SECRET
# Enter your client secret

# Generate and set encryption key (32 bytes = 64 hex chars)
npx wrangler secret put ENCRYPTION_KEY
# Enter: openssl rand -hex 32
```

### 4. Update wrangler.toml

Edit `wrangler.toml` and replace `your-kv-namespace-id` with your actual KV namespace ID:

```toml
[[kv_namespaces]]
binding = "AUTH_TOKENS"
id = "your-actual-kv-namespace-id"
```

### 5. Install Dependencies

```bash
npm install
```

### 6. Deploy

```bash
# Development
npm run dev

# Production
npm run deploy
```

## Local Development

```bash
# Start local dev server
npm run dev
```

The service will be available at `http://localhost:8787`.

For local development, you'll need to create a `.dev.vars` file:

```env
MICROSOFT_CLIENT_ID=your-client-id
MICROSOFT_CLIENT_SECRET=your-client-secret
ENCRYPTION_KEY=your-64-char-hex-key
```

## API Reference

### POST /auth/login

Start the OAuth flow by generating a Microsoft authorization URL.

**Request:**
```json
{
  "code_verifier": "a-random-43-128-character-string"
}
```

**Response:**
```json
{
  "auth_url": "https://login.microsoftonline.com/...",
  "state": "random-state-for-csrf"
}
```

### POST /auth/callback

Exchange the authorization code for tokens.

**Request:**
```json
{
  "code": "authorization-code-from-microsoft",
  "code_verifier": "same-verifier-from-login",
  "state": "state-from-login"
}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAi...",
  "user_id": "hashed-user-id",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

### POST /auth/refresh

Refresh the access token using the stored refresh token.

**Request:**
```json
{
  "user_id": "hashed-user-id-from-callback"
}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAi...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

### POST /auth/logout

Delete stored tokens for a user.

**Request:**
```json
{
  "user_id": "hashed-user-id"
}
```

**Response:**
```json
{
  "success": true
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "service": "onedrive-auth-service",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

## Security

### Token Encryption

Refresh tokens are encrypted using AES-256-GCM before storage:
- 256-bit key (from ENCRYPTION_KEY secret)
- Random 96-bit IV per encryption
- Authentication tag prevents tampering

### User ID Hashing

Microsoft user IDs are SHA-256 hashed:
- Original ID never stored
- First 32 characters of hash used as identifier
- Cannot be reversed to original ID

### CORS Policy

Only `http://localhost:8400` is allowed (the local callback server).

### Token Expiration

- Access tokens: ~1 hour (Microsoft default)
- Refresh tokens in KV: 90 days TTL
- After 90 days of inactivity, users must re-authenticate

## Client Integration

The Python client (`auth_client.py`) in the parent directory handles:
- PKCE code verifier generation
- Local HTTP server for OAuth callback
- Session persistence in `~/.onedrive_backup_session.json`

To use a custom auth service URL:

```python
from auth_client import SimpleAuth

auth = SimpleAuth(service_url='https://your-service.workers.dev')
```

Or set the environment variable:

```bash
export AUTH_SERVICE_URL=https://your-service.workers.dev
```

## Troubleshooting

### "Token exchange failed"

- Verify the redirect URI in Azure matches exactly: `http://localhost:8400/callback`
- Ensure the client secret hasn't expired
- Check that all required scopes are granted

### "No refresh token found"

- User's session expired (90 days)
- User needs to re-authenticate

### CORS errors

- Ensure the desktop app is using port 8400 for callbacks
- Check browser console for specific origin errors

## License

MIT License - see LICENSE.md in the repository root.
