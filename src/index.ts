import { Hono } from 'hono';
import { jwt } from 'hono/jwt';
import mongoose from 'mongoose';
import { createHash, randomBytes } from 'crypto';
import { Application, AuthorizationCode } from './models/application';

const app = new Hono();

// Helper function to verify client credentials
async function verifyClientCredentials(clientId: string, clientSecret: string) {
  const application = await Application.findOne({
    clientId,
    clientSecret,
    applicationType: 'confidential'
  });
  return application;
}

// Helper function to generate tokens
function generateTokens() {
  return {
    accessToken: randomBytes(32).toString('hex'),
    refreshToken: randomBytes(32).toString('hex')
  };
}

// Client Credentials Flow (Server-to-Server)
app.post('/oauth/token', async (c) => {
  const body = await c.req.parseBody();
  const {
    grant_type,
    client_id,
    client_secret,
    scope,
    code,
    redirect_uri,
    refresh_token,
    code_verifier
  } = body;

  // Handle Client Credentials Grant
  if (grant_type === 'client_credentials') {
    const application = await verifyClientCredentials(client_id, client_secret);
    if (!application) {
      return c.json({ error: 'invalid_client' }, 401);
    }

    // Validate requested scopes
    const requestedScopes = scope ? scope.split(' ') : [];
    const validScopes = requestedScopes.every((s) =>
      application.scopes.includes(s)
    );
    if (!validScopes) {
      return c.json({ error: 'invalid_scope' }, 400);
    }

    // Generate access token (no refresh token for client credentials)
    const { accessToken } = generateTokens();
    const token = new Token({
      accessToken,
      clientId: client_id,
      scopes: requestedScopes,
      expiresAt: new Date(Date.now() + 3600 * 1000),
      tokenType: 'bearer'
    });

    await token.save();

    return c.json({
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: 3600,
      scope: requestedScopes.join(' ')
    });
  }

  // Handle Authorization Code Grant
  if (grant_type === 'authorization_code') {
    const authCode = await AuthorizationCode.findOne({
      code,
      clientId: client_id
    });

    if (!authCode || authCode.expiresAt < new Date()) {
      return c.json({ error: 'invalid_grant' }, 400);
    }

    // Verify PKCE if code challenge exists
    if (authCode.codeChallenge) {
      if (!code_verifier) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'code_verifier required'
          },
          400
        );
      }

      const hash = createHash('sha256')
        .update(code_verifier)
        .digest('base64url');

      if (hash !== authCode.codeChallenge) {
        return c.json(
          {
            error: 'invalid_grant',
            error_description: 'code verifier mismatch'
          },
          400
        );
      }
    }

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens();
    const token = new Token({
      accessToken,
      refreshToken,
      clientId: client_id,
      userId: authCode.userId,
      scopes: authCode.scopes,
      expiresAt: new Date(Date.now() + 3600 * 1000),
      tokenType: 'bearer'
    });

    await token.save();
    await AuthorizationCode.deleteOne({ _id: authCode._id });

    return c.json({
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: authCode.scopes.join(' ')
    });
  }

  // Handle Refresh Token Grant
  if (grant_type === 'refresh_token') {
    const existingToken = await Token.findOne({
      refreshToken: refresh_token,
      clientId: client_id
    });

    if (!existingToken) {
      return c.json({ error: 'invalid_grant' }, 400);
    }

    // Generate new tokens
    const { accessToken, refreshToken } = generateTokens();
    const token = new Token({
      accessToken,
      refreshToken,
      clientId: client_id,
      userId: existingToken.userId,
      scopes: existingToken.scopes,
      expiresAt: new Date(Date.now() + 3600 * 1000),
      tokenType: 'bearer'
    });

    await token.save();
    await Token.deleteOne({ _id: existingToken._id });

    return c.json({
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: existingToken.scopes.join(' ')
    });
  }

  return c.json({ error: 'unsupported_grant_type' }, 400);
});

// Authorization Endpoint (for client-side apps)
app.get('/oauth/authorize', async (c) => {
  const {
    client_id,
    redirect_uri,
    scope,
    state,
    response_type,
    code_challenge,
    code_challenge_method
  } = c.req.query();

  const application = await Application.findOne({ clientId: client_id });

  if (!application || application.applicationType !== 'public') {
    return c.json({ error: 'unauthorized_client' }, 400);
  }

  if (!application.redirectUris.includes(redirect_uri)) {
    return c.json({ error: 'invalid_redirect_uri' }, 400);
  }

  // Store authorization request data
  const authCode = new AuthorizationCode({
    code: randomBytes(16).toString('hex'),
    clientId: client_id,
    userId: 'current-user-id', // Get from session
    scopes: scope?.split(' ') || [],
    redirectUri: redirect_uri,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
    expiresAt: new Date(Date.now() + 600000) // 10 minutes
  });

  await authCode.save();

  // Render consent page
  return c.html(`
    <h1>Authorize ${application.name}</h1>
    <p>This application would like to:</p>
    <ul>
      ${scope
        ?.split(' ')
        .map((s) => `<li>${s}</li>`)
        .join('')}
    </ul>
    <form method="post" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="${client_id}" />
      <input type="hidden" name="redirect_uri" value="${redirect_uri}" />
      <input type="hidden" name="state" value="${state}" />
      <input type="hidden" name="code" value="${authCode.code}" />
      <button type="submit">Authorize</button>
    </form>
  `);
});

// Handle authorization consent
app.post('/oauth/authorize', async (c) => {
  const body = await c.req.parseBody();
  const { client_id, redirect_uri, state, code } = body;

  const authCode = await AuthorizationCode.findOne({ code });
  if (!authCode) {
    return c.json({ error: 'invalid_request' }, 400);
  }

  // Redirect back to client with authorization code
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) {
    redirectUrl.searchParams.set('state', state);
  }

  return c.redirect(redirectUrl.toString());
});

export default app;
