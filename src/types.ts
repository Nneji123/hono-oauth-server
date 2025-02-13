// types.ts
interface OAuth2Application {
  clientId: string;
  clientSecret: string;
  name: string;
  description?: string;
  logoUrl?: string;
  redirectUris: string[];
  userId: string;
  scopes: string[];
  applicationType: 'confidential' | 'public'; // confidential for server-side, public for client-side
  createdAt: Date;
  updatedAt: Date;
}

interface OAuth2Token {
  accessToken: string;
  refreshToken?: string; // Optional for client credentials flow
  clientId: string;
  userId?: string; // Optional for client credentials flow
  scopes: string[];
  expiresAt: Date;
  tokenType: 'bearer';
  createdAt: Date;
}

interface AuthorizationCode {
  code: string;
  clientId: string;
  userId: string;
  scopes: string[];
  redirectUri: string;
  codeChallenge?: string;
  codeChallengeMethod?: 'S256' | 'plain';
  expiresAt: Date;
}

interface User {
  id: string;
  email: string;
  password: string;
  name: string;
  isAdmin: boolean;
  createdAt: Date;
}
