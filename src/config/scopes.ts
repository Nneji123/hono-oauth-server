export const AVAILABLE_SCOPES = {
  'read:profile': 'Read basic profile information',
  'write:profile': 'Update profile information',
  'read:email': 'Access email address',
  'read:users': 'Read users data',
  'write:users': 'Modify users data',
  'delete:users': 'Delete users',
  'read:apps': 'List OAuth applications',
  'write:apps': 'Manage OAuth applications'
} as const;
