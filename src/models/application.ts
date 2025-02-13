import mongoose from 'mongoose';
import crypto from 'crypto';

const applicationSchema = new mongoose.Schema({
  clientId: {
    type: String,
    unique: true,
    default: () => crypto.randomBytes(16).toString('hex')
  },
  clientSecret: {
    type: String,
    default: () => crypto.randomBytes(32).toString('hex')
  },
  name: { type: String, required: true },
  description: String,
  logoUrl: String,
  redirectUris: [{ type: String }], // Optional for server-to-server apps
  userId: { type: String, required: true },
  scopes: [String],
  applicationType: {
    type: String,
    enum: ['confidential', 'public'],
    required: true
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

export const Application = mongoose.model('Application', applicationSchema);

// models/authorizationCode.ts
const authorizationCodeSchema = new mongoose.Schema({
  code: { type: String, unique: true },
  clientId: { type: String, required: true },
  userId: { type: String, required: true },
  scopes: [String],
  redirectUri: { type: String, required: true },
  codeChallenge: String,
  codeChallengeMethod: { type: String, enum: ['S256', 'plain'] },
  expiresAt: { type: Date, required: true }
});

export const AuthorizationCode = mongoose.model(
  'AuthorizationCode',
  authorizationCodeSchema
);
