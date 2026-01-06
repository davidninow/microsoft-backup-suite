import { Hono } from 'hono';
import { cors } from 'hono/cors';

// Type definitions for Cloudflare environment
interface Env {
  AUTH_TOKENS: KVNamespace;
  MICROSOFT_CLIENT_ID: string;
  MICROSOFT_CLIENT_SECRET: string;
  ENCRYPTION_KEY: string; // 32-byte hex string for AES-256
}

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
  scope: string;
  id_token?: string;
}

interface UserInfo {
  id: string;
  displayName?: string;
  mail?: string;
  userPrincipalName?: string;
}

const app = new Hono<{ Bindings: Env }>();

// Constants
const REDIRECT_URI = 'http://localhost:8400/callback';
const SCOPES = 'Files.Read.All offline_access openid profile';
const TOKEN_ENDPOINT = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token';
const AUTHORIZE_ENDPOINT = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize';
const USERINFO_ENDPOINT = 'https://graph.microsoft.com/v1.0/me';

// KV expiration: 90 days in seconds
const KV_EXPIRATION_TTL = 90 * 24 * 60 * 60;

// CORS middleware - only allow localhost:8400
app.use('*', cors({
  origin: ['http://localhost:8400'],
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
}));

// ============================================================================
// Crypto utilities
// ============================================================================

/**
 * Hash a string using SHA-256 and return hex string
 */
async function sha256Hash(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate PKCE code challenge from code verifier (S256 method)
 */
async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  // Base64 URL encode
  const base64 = btoa(String.fromCharCode(...new Uint8Array(digest)));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Import encryption key from hex string
 */
async function importKey(keyHex: string): Promise<CryptoKey> {
  const keyBytes = new Uint8Array(keyHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
  return crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt data using AES-256-GCM
 */
async function encrypt(plaintext: string, keyHex: string): Promise<string> {
  const key = await importKey(keyHex);
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(plaintext)
  );

  // Combine IV + ciphertext and encode as base64
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.length);

  return btoa(String.fromCharCode(...combined));
}

/**
 * Decrypt data using AES-256-GCM
 */
async function decrypt(ciphertext: string, keyHex: string): Promise<string> {
  const key = await importKey(keyHex);
  const combined = new Uint8Array(
    atob(ciphertext).split('').map(c => c.charCodeAt(0))
  );

  const iv = combined.slice(0, 12);
  const data = combined.slice(12);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );

  return new TextDecoder().decode(decrypted);
}

// ============================================================================
// API Endpoints
// ============================================================================

/**
 * GET /health - Health check endpoint
 */
app.get('/health', (c) => {
  return c.json({
    status: 'ok',
    service: 'onedrive-auth-service',
    timestamp: new Date().toISOString(),
  });
});

/**
 * POST /auth/login - Start OAuth flow
 *
 * Request body: { code_verifier: string }
 * Response: { auth_url: string, state: string }
 */
app.post('/auth/login', async (c) => {
  try {
    const body = await c.req.json();
    const { code_verifier } = body;

    if (!code_verifier || typeof code_verifier !== 'string' || code_verifier.length < 43) {
      return c.json({ error: 'Invalid code_verifier. Must be at least 43 characters.' }, 400);
    }

    // Generate code challenge from verifier (S256)
    const code_challenge = await generateCodeChallenge(code_verifier);

    // Generate random state for CSRF protection
    const state = crypto.randomUUID();

    // Build Microsoft OAuth URL
    const params = new URLSearchParams({
      client_id: c.env.MICROSOFT_CLIENT_ID,
      response_type: 'code',
      redirect_uri: REDIRECT_URI,
      scope: SCOPES,
      response_mode: 'query',
      state: state,
      code_challenge: code_challenge,
      code_challenge_method: 'S256',
    });

    const auth_url = `${AUTHORIZE_ENDPOINT}?${params.toString()}`;

    return c.json({
      auth_url,
      state,
    });
  } catch (error) {
    console.error('Login error:', error);
    return c.json({ error: 'Failed to generate auth URL' }, 500);
  }
});

/**
 * POST /auth/callback - Exchange code for tokens
 *
 * Request body: { code: string, code_verifier: string, state: string }
 * Response: { access_token: string, user_id: string, expires_in: number }
 */
app.post('/auth/callback', async (c) => {
  try {
    const body = await c.req.json();
    const { code, code_verifier, state } = body;

    if (!code || !code_verifier) {
      return c.json({ error: 'Missing required parameters: code, code_verifier' }, 400);
    }

    // Exchange authorization code for tokens
    const tokenResponse = await fetch(TOKEN_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: c.env.MICROSOFT_CLIENT_ID,
        client_secret: c.env.MICROSOFT_CLIENT_SECRET,
        code: code,
        redirect_uri: REDIRECT_URI,
        grant_type: 'authorization_code',
        code_verifier: code_verifier,
      }),
    });

    const tokenData: TokenResponse = await tokenResponse.json();

    if (!tokenResponse.ok || !tokenData.access_token) {
      console.error('Token exchange failed:', tokenData);
      return c.json({
        error: 'Token exchange failed',
        details: (tokenData as any).error_description || 'Unknown error'
      }, 400);
    }

    // Get user info to create a stable user ID
    const userResponse = await fetch(USERINFO_ENDPOINT, {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
      },
    });

    if (!userResponse.ok) {
      return c.json({ error: 'Failed to fetch user info' }, 500);
    }

    const userInfo: UserInfo = await userResponse.json();

    // Hash the Microsoft user ID (never store raw)
    const hashedUserId = await sha256Hash(userInfo.id);
    // Use first 32 chars as user_id for the client
    const user_id = hashedUserId.substring(0, 32);

    // Encrypt and store refresh token in KV
    if (tokenData.refresh_token) {
      const encryptedRefreshToken = await encrypt(tokenData.refresh_token, c.env.ENCRYPTION_KEY);
      await c.env.AUTH_TOKENS.put(
        `refresh:${user_id}`,
        encryptedRefreshToken,
        { expirationTtl: KV_EXPIRATION_TTL }
      );
    }

    return c.json({
      access_token: tokenData.access_token,
      user_id: user_id,
      expires_in: tokenData.expires_in,
      token_type: tokenData.token_type,
    });
  } catch (error) {
    console.error('Callback error:', error);
    return c.json({ error: 'Failed to exchange code for tokens' }, 500);
  }
});

/**
 * POST /auth/refresh - Refresh access token
 *
 * Request body: { user_id: string }
 * Response: { access_token: string, expires_in: number }
 */
app.post('/auth/refresh', async (c) => {
  try {
    const body = await c.req.json();
    const { user_id } = body;

    if (!user_id || typeof user_id !== 'string') {
      return c.json({ error: 'Missing user_id' }, 400);
    }

    // Retrieve encrypted refresh token from KV
    const encryptedRefreshToken = await c.env.AUTH_TOKENS.get(`refresh:${user_id}`);

    if (!encryptedRefreshToken) {
      return c.json({ error: 'No refresh token found. Please login again.' }, 401);
    }

    // Decrypt refresh token
    const refresh_token = await decrypt(encryptedRefreshToken, c.env.ENCRYPTION_KEY);

    // Exchange refresh token for new access token
    const tokenResponse = await fetch(TOKEN_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: c.env.MICROSOFT_CLIENT_ID,
        client_secret: c.env.MICROSOFT_CLIENT_SECRET,
        refresh_token: refresh_token,
        grant_type: 'refresh_token',
        scope: SCOPES,
      }),
    });

    const tokenData: TokenResponse = await tokenResponse.json();

    if (!tokenResponse.ok || !tokenData.access_token) {
      console.error('Token refresh failed:', tokenData);
      // If refresh failed, delete the stored token
      await c.env.AUTH_TOKENS.delete(`refresh:${user_id}`);
      return c.json({
        error: 'Token refresh failed. Please login again.',
        details: (tokenData as any).error_description || 'Unknown error'
      }, 401);
    }

    // If we got a new refresh token, update the stored one
    if (tokenData.refresh_token) {
      const encryptedNewRefreshToken = await encrypt(tokenData.refresh_token, c.env.ENCRYPTION_KEY);
      await c.env.AUTH_TOKENS.put(
        `refresh:${user_id}`,
        encryptedNewRefreshToken,
        { expirationTtl: KV_EXPIRATION_TTL }
      );
    }

    return c.json({
      access_token: tokenData.access_token,
      expires_in: tokenData.expires_in,
      token_type: tokenData.token_type,
    });
  } catch (error) {
    console.error('Refresh error:', error);
    return c.json({ error: 'Failed to refresh token' }, 500);
  }
});

/**
 * POST /auth/logout - Delete stored tokens
 *
 * Request body: { user_id: string }
 * Response: { success: boolean }
 */
app.post('/auth/logout', async (c) => {
  try {
    const body = await c.req.json();
    const { user_id } = body;

    if (!user_id || typeof user_id !== 'string') {
      return c.json({ error: 'Missing user_id' }, 400);
    }

    // Delete refresh token from KV
    await c.env.AUTH_TOKENS.delete(`refresh:${user_id}`);

    return c.json({ success: true });
  } catch (error) {
    console.error('Logout error:', error);
    return c.json({ error: 'Failed to logout' }, 500);
  }
});

// 404 handler
app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

// Error handler
app.onError((err, c) => {
  console.error('Unhandled error:', err);
  return c.json({ error: 'Internal server error' }, 500);
});

export default app;
