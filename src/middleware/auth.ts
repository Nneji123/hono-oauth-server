import { Context, Next } from 'hono';
import { verify } from 'hono/jwt';

export async function requireAuth(c: Context, next: Next) {
  const authHeader = c.req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return c.json({ error: 'unauthorized' }, 401);
  }

  try {
    const token = authHeader.split(' ')[1];
    const payload = await verify(token, process.env.JWT_SECRET!);
    c.set('user', payload);
    await next();
  } catch {
    return c.json({ error: 'invalid_token' }, 401);
  }
}

export async function requireAdmin(c: Context, next: Next) {
  const user = c.get('user');
  if (!user.isAdmin) {
    return c.json({ error: 'forbidden' }, 403);
  }
  await next();
}
