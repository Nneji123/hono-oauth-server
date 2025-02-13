import { Hono } from 'hono';
import { User } from '../models/user';
import { requireAuth, requireAdmin } from '../middleware/auth';
import { rateLimit } from '../middleware/rate-limit';

const users = new Hono();

users.use('*', rateLimit(100, 60 * 1000)); // 100 requests per minute

users.post('/register', async (c) => {
  const { email, password, name } = await c.req.json();

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return c.json({ error: 'email_taken' }, 400);
  }

  const user = new User({ email, password, name });
  await user.save();

  return c.json({
    id: user.id,
    email: user.email,
    name: user.name
  });
});

users.post('/login', async (c) => {
  const { email, password } = await c.req.json();

  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return c.json({ error: 'invalid_credentials' }, 401);
  }

  const token = await sign(
    {
      sub: user.id,
      email: user.email,
      isAdmin: user.isAdmin
    },
    process.env.JWT_SECRET!
  );

  return c.json({ token });
});

users.get('/me', requireAuth, async (c) => {
  const user = await User.findById(c.get('user').sub);
  if (!user) {
    return c.json({ error: 'user_not_found' }, 404);
  }

  return c.json({
    id: user.id,
    email: user.email,
    name: user.name,
    isAdmin: user.isAdmin
  });
});

users.get('/users', requireAuth, requireAdmin, async (c) => {
  const users = await User.find().select('-password');
  return c.json(users);
});

export { users };
