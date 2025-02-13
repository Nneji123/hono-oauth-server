import { Context, Next } from 'hono';
import { Cache } from 'hono/utils/cache';

const cache = new Cache();

export function rateLimit(requests: number, windowMs: number) {
  return async (c: Context, next: Next) => {
    const ip = c.req.header('x-forwarded-for') || 'unknown';
    const key = `${ip}:${c.req.path}`;

    const current = cache.get(key) || 0;
    if (current >= requests) {
      return c.json(
        {
          error: 'too_many_requests',
          error_description: 'Rate limit exceeded'
        },
        429
      );
    }

    cache.set(key, current + 1, windowMs);
    await next();
  };
}
