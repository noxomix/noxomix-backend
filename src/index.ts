import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { bearerAuth } from 'hono/bearer-auth';
import { db } from './db';
import { users, posts, servers } from './db/schema';
import { eq, like, or, desc, asc, count } from 'drizzle-orm';
import { hashPassword, verifyPassword, createApiToken, validateApiToken, validateAdminToken } from './auth';

const app = new Hono();

app.use('*', logger());
app.use('*', cors({
  origin: ['http://localhost:5173', 'http://localhost:3000'],
  credentials: true,
}));

app.get('/', (c) => {
  return c.json({ message: 'Hono.js Backend with Drizzle ORM' });
});

// Auth middleware
const authMiddleware = async (c: any, next: any) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  
  const token = authHeader.substring(7);
  const validation = await validateApiToken(token);
  
  if (!validation) {
    return c.json({ error: 'Invalid token' }, 401);
  }
  
  c.set('userId', validation.userId);
  await next();
};

// Admin middleware
const adminMiddleware = async (c: any, next: any) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  
  const token = authHeader.substring(7);
  const validation = await validateAdminToken(token);
  
  if (!validation) {
    return c.json({ error: 'Admin access required' }, 403);
  }
  
  c.set('userId', validation.userId);
  c.set('isAdmin', validation.isAdmin);
  await next();
};

// Auth routes
app.post('/auth/register', async (c) => {
  try {
    const { name, email, password, role } = await c.req.json();
    
    if (!name || !email || !password) {
      return c.json({ error: 'Name, email and password are required' }, 400);
    }
    
    const existingUser = await db.select().from(users).where(eq(users.email, email));
    if (existingUser.length > 0) {
      return c.json({ error: 'User already exists' }, 400);
    }
    
    const hashedPassword = await hashPassword(password);
    const newUser = await db.insert(users).values({
      name,
      email,
      password: hashedPassword,
      role: role || 'customer',
    }).returning();
    
    const token = await createApiToken(newUser[0].id);
    
    const { password: _, ...userWithoutPassword } = newUser[0];
    return c.json({ user: userWithoutPassword, token }, 201);
  } catch (error) {
    return c.json({ error: 'Failed to register user' }, 500);
  }
});

app.post('/auth/login', async (c) => {
  try {
    const { email, password } = await c.req.json();
    
    if (!email || !password) {
      return c.json({ error: 'Email and password are required' }, 400);
    }
    
    const user = await db.select().from(users).where(eq(users.email, email));
    if (user.length === 0) {
      return c.json({ error: 'Invalid credentials' }, 401);
    }
    
    const isValidPassword = await verifyPassword(password, user[0].password);
    if (!isValidPassword) {
      return c.json({ error: 'Invalid credentials' }, 401);
    }
    
    const token = await createApiToken(user[0].id);
    
    const { password: _, ...userWithoutPassword } = user[0];
    return c.json({ user: userWithoutPassword, token });
  } catch (error) {
    return c.json({ error: 'Failed to login' }, 500);
  }
});

app.get('/auth/me', authMiddleware, async (c) => {
  try {
    const userId = c.get('userId');
    const user = await db.select().from(users).where(eq(users.id, userId));
    
    if (user.length === 0) {
      return c.json({ error: 'User not found' }, 404);
    }
    
    const { password: _, ...userWithoutPassword } = user[0];
    return c.json({ user: userWithoutPassword });
  } catch (error) {
    return c.json({ error: 'Failed to get user' }, 500);
  }
});

// Protected routes
app.get('/users', authMiddleware, async (c) => {
  try {
    const allUsers = await db.select().from(users);
    return c.json(allUsers);
  } catch (error) {
    return c.json({ error: 'Failed to fetch users' }, 500);
  }
});

app.post('/users', async (c) => {
  try {
    const { name, email } = await c.req.json();
    const newUser = await db.insert(users).values({ name, email }).returning();
    return c.json(newUser[0], 201);
  } catch (error) {
    return c.json({ error: 'Failed to create user' }, 500);
  }
});

app.get('/users/:id', async (c) => {
  try {
    const id = parseInt(c.req.param('id'));
    const user = await db.select().from(users).where(eq(users.id, id));
    if (user.length === 0) {
      return c.json({ error: 'User not found' }, 404);
    }
    return c.json(user[0]);
  } catch (error) {
    return c.json({ error: 'Failed to fetch user' }, 500);
  }
});

app.get('/posts', async (c) => {
  try {
    const allPosts = await db.select().from(posts);
    return c.json(allPosts);
  } catch (error) {
    return c.json({ error: 'Failed to fetch posts' }, 500);
  }
});

app.post('/posts', async (c) => {
  try {
    const { title, content, authorId } = await c.req.json();
    const newPost = await db.insert(posts).values({ title, content, authorId }).returning();
    return c.json(newPost[0], 201);
  } catch (error) {
    return c.json({ error: 'Failed to create post' }, 500);
  }
});

// Admin User Management endpoint
app.get('/api/admin/users', adminMiddleware, async (c) => {
  try {
    // Get query parameters with validation
    const page = Math.max(1, parseInt(c.req.query('page') || '1'));
    const limit = Math.min(Math.max(1, parseInt(c.req.query('limit') || '10')), 100);
    const search = c.req.query('search')?.trim() || '';
    const sortBy = c.req.query('sortBy') || 'createdAt';
    const sortOrder = c.req.query('sortOrder') === 'asc' ? 'asc' : 'desc';
    
    // Validate sortBy parameter to prevent injection
    const allowedSortFields = ['id', 'name', 'email', 'role', 'createdAt', 'updatedAt'];
    const safeSortBy = allowedSortFields.includes(sortBy) ? sortBy : 'createdAt';
    
    const offset = (page - 1) * limit;
    
    // Build search conditions
    let whereConditions = undefined;
    if (search) {
      // SQL injection safe search using Drizzle ORM
      whereConditions = or(
        like(users.name, `%${search}%`),
        like(users.email, `%${search}%`)
      );
    }
    
    // Get total count for pagination
    const totalCountResult = await db
      .select({ count: count() })
      .from(users)
      .where(whereConditions);
    
    const totalUsers = totalCountResult[0].count;
    const totalPages = Math.ceil(totalUsers / limit);
    
    // Get users with pagination and sorting
    const sortColumn = users[safeSortBy as keyof typeof users];
    const orderBy = sortOrder === 'asc' ? asc(sortColumn) : desc(sortColumn);
    
    const userList = await db
      .select({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        createdAt: users.createdAt,
        updatedAt: users.updatedAt,
      })
      .from(users)
      .where(whereConditions)
      .orderBy(orderBy)
      .limit(limit)
      .offset(offset);
    
    return c.json({
      users: userList,
      pagination: {
        page,
        limit,
        totalUsers,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
      search,
      sortBy: safeSortBy,
      sortOrder,
    });
  } catch (error) {
    console.error('Error fetching users for admin:', error);
    return c.json({ error: 'Failed to fetch users' }, 500);
  }
});

// Server endpoints
app.get('/api/servers', authMiddleware, async (c) => {
  try {
    const userId = c.get('userId');

    const userServers = await db.select().from(servers).where(eq(servers.userId, userId));
    
    // Transform data to match frontend expectations
    const transformedServers = userServers.map(server => ({
      id: server.id,
      name: `${server.subdomain}.${server.host}`,
      status: server.status === 'running' ? 'Online' : 
              server.status === 'stopped' ? 'Offline' : 
              server.status === 'starting' ? 'Loading' : 'Offline',
      cpu: server.cpuCores,
      ram: `${server.ram}MB`,
      storage: `${server.storage}GB`,
      subdomain: server.subdomain,
      host: server.host,
      serverVersion: server.serverVersion,
      minecraftVersion: server.minecraftVersion,
      createdAt: server.createdAt,
      lastActiveAt: server.lastActiveAt
    }));

    return c.json({ servers: transformedServers });
  } catch (error) {
    console.error('Error fetching servers:', error);
    return c.json({ error: 'Failed to fetch servers' }, 500);
  }
});

const port = parseInt(process.env.PORT || '3000');

export default {
  port,
  fetch: app.fetch,
};