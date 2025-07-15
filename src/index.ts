import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { bearerAuth } from 'hono/bearer-auth';
import { db } from './db';
import { users, posts, servers, domains, apiTokens, subdomains } from './db/schema';
import { eq, like, or, desc, asc, count, and, ne } from 'drizzle-orm';
import { hashPassword, verifyPassword, createApiToken, validateApiToken, validateAdminToken } from './auth';

const app = new Hono();

app.use('*', logger());
app.use('*', cors({
  origin: '*',
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
    
    // Check if user is enabled
    if (!user[0].enabled) {
      return c.json({ error: 'Account is disabled. Please contact an administrator.' }, 403);
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
    const allowedSortFields = ['id', 'name', 'email', 'role', 'enabled', 'createdAt', 'updatedAt'];
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
        enabled: users.enabled,
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

// Domain endpoints (admin only)
app.get('/api/admin/domains', adminMiddleware, async (c) => {
  try {
    // Get pagination and search parameters
    const page = parseInt(c.req.query('page') || '1');
    const limit = parseInt(c.req.query('limit') || '10');
    const search = c.req.query('search') || '';
    const sortBy = c.req.query('sortBy') || 'createdAt';
    const sortOrder = c.req.query('sortOrder') || 'desc';
    
    // Validate pagination
    const safePage = Math.max(1, page);
    const safeLimit = Math.min(Math.max(1, limit), 100);
    const offset = (safePage - 1) * safeLimit;
    
    // Validate sort column
    const validSortColumns = ['name', 'enabled', 'createdAt', 'updatedAt'];
    const safeSortBy = validSortColumns.includes(sortBy) ? sortBy : 'createdAt';
    
    // Build search conditions
    let whereConditions = undefined;
    if (search) {
      whereConditions = like(domains.name, `%${search}%`);
    }
    
    // Get total count for pagination
    const totalCountResult = await db
      .select({ count: count() })
      .from(domains)
      .where(whereConditions);
    
    const totalDomains = totalCountResult[0].count;
    const totalPages = Math.ceil(totalDomains / safeLimit);
    
    // Get domains with pagination and sorting
    const sortColumn = domains[safeSortBy as keyof typeof domains];
    const orderBy = sortOrder === 'asc' ? asc(sortColumn) : desc(sortColumn);
    
    const domainList = await db
      .select()
      .from(domains)
      .where(whereConditions)
      .orderBy(orderBy)
      .limit(safeLimit)
      .offset(offset);
    
    return c.json({
      domains: domainList,
      pagination: {
        page: safePage,
        limit: safeLimit,
        totalDomains,
        totalPages,
        hasNextPage: safePage < totalPages,
        hasPrevPage: safePage > 1,
      },
      search,
      sortBy: safeSortBy,
      sortOrder,
    });
  } catch (error) {
    console.error('Error fetching domains:', error);
    return c.json({ error: 'Failed to fetch domains' }, 500);
  }
});

app.post('/api/admin/domains', adminMiddleware, async (c) => {
  try {
    const body = await c.req.json();
    
    // Validate input
    if (!body.name || typeof body.name !== 'string') {
      return c.json({ error: 'Domain name is required' }, 400);
    }
    
    // Validate domain name format
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(body.name)) {
      return c.json({ error: 'Invalid domain name format' }, 400);
    }
    
    // Validate enabled field if provided
    if (body.enabled && !['enabled', 'disabled'].includes(body.enabled)) {
      return c.json({ error: 'Invalid enabled value. Must be "enabled" or "disabled"' }, 400);
    }
    
    // Validate bunnyId if provided
    let bunnyId = body.bunnyId;
    if (bunnyId === '' || bunnyId === undefined) {
      bunnyId = null;
    }
    
    if (bunnyId !== null) {
      if (!Number.isInteger(bunnyId) || bunnyId < 1) {
        return c.json({ error: 'Invalid bunnyId. Must be a positive integer or null' }, 400);
      }
    }
    
    // Check if domain already exists
    const existingDomain = await db
      .select()
      .from(domains)
      .where(eq(domains.name, body.name))
      .limit(1);
    
    if (existingDomain.length > 0) {
      return c.json({ error: 'Domain already exists' }, 409);
    }
    
    // Create domain
    const [newDomain] = await db.insert(domains).values({
      name: body.name,
      bunnyId: bunnyId,
      enabled: body.enabled || 'enabled',
    });
    
    // Fetch the created domain
    const createdDomain = await db
      .select()
      .from(domains)
      .where(eq(domains.name, body.name))
      .limit(1);
    
    return c.json({ domain: createdDomain[0] }, 201);
  } catch (error) {
    console.error('Error creating domain:', error);
    return c.json({ error: 'Failed to create domain' }, 500);
  }
});

app.put('/api/admin/domains/:id', adminMiddleware, async (c) => {
  try {
    const domainId = parseInt(c.req.param('id'));
    const body = await c.req.json();
    
    if (isNaN(domainId)) {
      return c.json({ error: 'Invalid domain ID' }, 400);
    }
    
    // Check if domain exists
    const existingDomain = await db
      .select()
      .from(domains)
      .where(eq(domains.id, domainId))
      .limit(1);
    
    if (existingDomain.length === 0) {
      return c.json({ error: 'Domain not found' }, 404);
    }
    
    // Prepare update data
    const updateData: any = {};
    
    // Validate and update name if provided
    if (body.name !== undefined) {
      if (typeof body.name !== 'string' || body.name.trim() === '') {
        return c.json({ error: 'Invalid domain name' }, 400);
      }
      
      const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
      if (!domainRegex.test(body.name)) {
        return c.json({ error: 'Invalid domain name format' }, 400);
      }
      
      // Check if new name already exists (excluding current domain)
      const duplicateDomain = await db
        .select()
        .from(domains)
        .where(eq(domains.name, body.name))
        .limit(1);
      
      if (duplicateDomain.length > 0 && duplicateDomain[0].id !== domainId) {
        return c.json({ error: 'Domain name already exists' }, 409);
      }
      
      updateData.name = body.name;
    }
    
    // Validate and update enabled status if provided
    if (body.enabled !== undefined) {
      if (!['enabled', 'disabled'].includes(body.enabled)) {
        return c.json({ error: 'Invalid enabled value. Must be "enabled" or "disabled"' }, 400);
      }
      updateData.enabled = body.enabled;
    }
    
    // Validate and update bunnyId if provided
    if (body.bunnyId !== undefined) {
      // Convert empty string to null
      let bunnyId = body.bunnyId;
      if (bunnyId === '' || bunnyId === undefined) {
        bunnyId = null;
      }
      
      if (bunnyId !== null && (!Number.isInteger(bunnyId) || bunnyId < 1)) {
        return c.json({ error: 'Invalid bunnyId. Must be a positive integer or null' }, 400);
      }
      updateData.bunnyId = bunnyId;
    }
    
    if (Object.keys(updateData).length === 0) {
      return c.json({ error: 'No valid fields to update' }, 400);
    }
    
    // Update domain
    await db
      .update(domains)
      .set(updateData)
      .where(eq(domains.id, domainId));
    
    // Fetch updated domain
    const updatedDomain = await db
      .select()
      .from(domains)
      .where(eq(domains.id, domainId))
      .limit(1);
    
    return c.json({ domain: updatedDomain[0] });
  } catch (error) {
    console.error('Error updating domain:', error);
    return c.json({ error: 'Failed to update domain' }, 500);
  }
});

app.delete('/api/admin/domains/:id', adminMiddleware, async (c) => {
  try {
    const domainId = parseInt(c.req.param('id'));
    
    if (isNaN(domainId)) {
      return c.json({ error: 'Invalid domain ID' }, 400);
    }
    
    // Check if domain exists
    const existingDomain = await db
      .select()
      .from(domains)
      .where(eq(domains.id, domainId))
      .limit(1);
    
    if (existingDomain.length === 0) {
      return c.json({ error: 'Domain not found' }, 404);
    }
    
    // Check if domain is enabled
    if (existingDomain[0].enabled === 'enabled') {
      return c.json({ error: 'Cannot delete enabled domains. Please disable the domain first.' }, 400);
    }
    
    // Delete domain
    await db.delete(domains).where(eq(domains.id, domainId));
    
    return c.json({ message: 'Domain deleted successfully' });
  } catch (error) {
    console.error('Error deleting domain:', error);
    return c.json({ error: 'Failed to delete domain' }, 500);
  }
});

// Link domain to Bunny CDN endpoint (admin only)
app.post('/api/admin/domains/:id/link-bunny', adminMiddleware, async (c) => {
  try {
    const domainId = parseInt(c.req.param('id'));
    
    if (isNaN(domainId)) {
      return c.json({ error: 'Invalid domain ID' }, 400);
    }
    
    // Check if domain exists
    const existingDomain = await db
      .select()
      .from(domains)
      .where(eq(domains.id, domainId))
      .limit(1);
    
    if (existingDomain.length === 0) {
      return c.json({ error: 'Domain not found' }, 404);
    }
    
    const domain = existingDomain[0];
    
    // Check if domain is already linked to Bunny
    if (domain.bunnyId) {
      return c.json({ error: 'Domain is already linked to Bunny CDN' }, 400);
    }
    
    // Get Bunny API key from environment
    const bunnyApiKey = process.env.BUNNY_API_KEY;
    if (!bunnyApiKey) {
      console.error('BUNNY_API_KEY not configured');
      return c.json({ error: 'Bunny CDN integration not configured' }, 500);
    }
    
    try {
      // Call Bunny API to create DNS zone
      const bunnyResponse = await fetch('https://api.bunny.net/dnszone', {
        method: 'POST',
        headers: {
          'accept': 'application/json',
          'content-type': 'application/json',
          'AccessKey': bunnyApiKey
        },
        body: JSON.stringify({
          Domain: domain.name
        })
      });
      
      if (!bunnyResponse.ok) {
        const errorText = await bunnyResponse.text();
        console.error('Bunny API error:', bunnyResponse.status, errorText);
        return c.json({ 
          error: `Failed to create DNS zone in Bunny CDN: ${bunnyResponse.status} ${bunnyResponse.statusText}` 
        }, 500);
      }
      
      const bunnyData = await bunnyResponse.json();
      console.log('Bunny API response:', bunnyData);
      
      // Extract the DNS zone ID from Bunny response
      const bunnyId = bunnyData.Id;
      if (!bunnyId) {
        console.error('No ID returned from Bunny API:', bunnyData);
        return c.json({ error: 'Invalid response from Bunny CDN API' }, 500);
      }
      
      // Update domain with Bunny ID
      await db
        .update(domains)
        .set({ bunnyId: bunnyId })
        .where(eq(domains.id, domainId));
      
      return c.json({ 
        message: 'Domain successfully linked to Bunny CDN',
        bunnyId: bunnyId,
        domain: domain.name
      });
      
    } catch (fetchError) {
      console.error('Error calling Bunny API:', fetchError);
      return c.json({ error: 'Failed to connect to Bunny CDN API' }, 500);
    }
    
  } catch (error) {
    console.error('Error linking domain to Bunny:', error);
    return c.json({ error: 'Failed to link domain to Bunny CDN' }, 500);
  }
});

// Subdomain endpoints (admin only)
app.get('/api/admin/domains/:domainId/subdomains', adminMiddleware, async (c) => {
  try {
    const domainId = parseInt(c.req.param('domainId'));
    
    if (isNaN(domainId)) {
      return c.json({ error: 'Invalid domain ID' }, 400);
    }
    
    // Check if domain exists
    const domain = await db
      .select()
      .from(domains)
      .where(eq(domains.id, domainId))
      .limit(1);
    
    if (domain.length === 0) {
      return c.json({ error: 'Domain not found' }, 404);
    }
    
    // Get pagination and search parameters
    const page = Math.max(1, parseInt(c.req.query('page') || '1'));
    const limit = Math.min(Math.max(1, parseInt(c.req.query('limit') || '10')), 100);
    const search = c.req.query('search') || '';
    const sortBy = c.req.query('sortBy') || 'createdAt';
    const sortOrder = c.req.query('sortOrder') || 'desc';
    
    const offset = (page - 1) * limit;
    
    // Validate sort column
    const validSortColumns = ['content', 'enabled', 'createdAt', 'updatedAt'];
    const safeSortBy = validSortColumns.includes(sortBy) ? sortBy : 'createdAt';
    
    // Build search conditions
    let whereConditions = eq(subdomains.domainId, domainId);
    if (search) {
      whereConditions = and(
        whereConditions,
        like(subdomains.content, `%${search}%`)
      );
    }
    
    // Get total count for pagination
    const totalCountResult = await db
      .select({ count: count() })
      .from(subdomains)
      .where(whereConditions);
    
    const totalSubdomains = totalCountResult[0].count;
    const totalPages = Math.ceil(totalSubdomains / limit);
    
    // Get subdomains with pagination and sorting
    const sortColumn = subdomains[safeSortBy as keyof typeof subdomains];
    const orderBy = sortOrder === 'asc' ? asc(sortColumn) : desc(sortColumn);
    
    const subdomainList = await db
      .select()
      .from(subdomains)
      .where(whereConditions)
      .orderBy(orderBy)
      .limit(limit)
      .offset(offset);
    
    return c.json({
      subdomains: subdomainList,
      domain: domain[0],
      pagination: {
        page,
        limit,
        totalSubdomains,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
      },
      search,
      sortBy: safeSortBy,
      sortOrder,
    });
  } catch (error) {
    console.error('Error fetching subdomains:', error);
    return c.json({ error: 'Failed to fetch subdomains' }, 500);
  }
});

app.post('/api/admin/domains/:domainId/subdomains', adminMiddleware, async (c) => {
  try {
    const domainId = parseInt(c.req.param('domainId'));
    const body = await c.req.json();
    
    if (isNaN(domainId)) {
      return c.json({ error: 'Invalid domain ID' }, 400);
    }
    
    // Check if domain exists
    const domain = await db
      .select()
      .from(domains)
      .where(eq(domains.id, domainId))
      .limit(1);
    
    if (domain.length === 0) {
      return c.json({ error: 'Domain not found' }, 404);
    }
    
    // Validate input
    if (!body.content || typeof body.content !== 'string' || body.content.trim() === '') {
      return c.json({ error: 'Subdomain content is required' }, 400);
    }
    
    // Validate subdomain format (only subdomain part, not full domain)
    const subdomainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
    if (!subdomainRegex.test(body.content)) {
      return c.json({ error: 'Invalid subdomain format. Must be only the subdomain part (e.g., mc)' }, 400);
    }
    
    // Construct the full domain name
    const fullDomain = `${body.content}.${domain[0].name}`;
    
    // Validate IP addresses if provided
    if (body.ipv4 && typeof body.ipv4 === 'string') {
      const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      if (!ipv4Regex.test(body.ipv4)) {
        return c.json({ error: 'Invalid IPv4 address format' }, 400);
      }
    }
    
    if (body.ipv6 && typeof body.ipv6 === 'string') {
      const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
      if (!ipv6Regex.test(body.ipv6)) {
        return c.json({ error: 'Invalid IPv6 address format' }, 400);
      }
    }
    
    // Validate record IDs if provided
    if (body.ipv4RecordId !== undefined && body.ipv4RecordId !== null && body.ipv4RecordId !== '') {
      const recordId = parseInt(body.ipv4RecordId);
      if (isNaN(recordId) || recordId < 1) {
        return c.json({ error: 'IPv4 Record ID must be a positive integer or empty' }, 400);
      }
      body.ipv4RecordId = recordId;
    } else {
      body.ipv4RecordId = null;
    }
    
    if (body.ipv6RecordId !== undefined && body.ipv6RecordId !== null && body.ipv6RecordId !== '') {
      const recordId = parseInt(body.ipv6RecordId);
      if (isNaN(recordId) || recordId < 1) {
        return c.json({ error: 'IPv6 Record ID must be a positive integer or empty' }, 400);
      }
      body.ipv6RecordId = recordId;
    } else {
      body.ipv6RecordId = null;
    }
    
    // Check if subdomain already exists
    const existingSubdomain = await db
      .select()
      .from(subdomains)
      .where(eq(subdomains.content, fullDomain.toLowerCase()))
      .limit(1);
    
    if (existingSubdomain.length > 0) {
      return c.json({ error: 'Subdomain already exists' }, 409);
    }
    
    // Create subdomain
    const [newSubdomain] = await db.insert(subdomains).values({
      domainId: domainId,
      content: fullDomain.toLowerCase(),
      ipv4: body.ipv4 || null,
      ipv6: body.ipv6 || null,
      ipv4RecordId: body.ipv4RecordId,
      ipv6RecordId: body.ipv6RecordId,
      enabled: body.enabled !== undefined ? body.enabled : true,
    });
    
    // Fetch the created subdomain
    const createdSubdomain = await db
      .select()
      .from(subdomains)
      .where(eq(subdomains.content, fullDomain.toLowerCase()))
      .limit(1);
    
    return c.json({ subdomain: createdSubdomain[0] }, 201);
  } catch (error) {
    console.error('Error creating subdomain:', error);
    return c.json({ error: 'Failed to create subdomain' }, 500);
  }
});

app.put('/api/admin/subdomains/:id', adminMiddleware, async (c) => {
  try {
    const subdomainId = parseInt(c.req.param('id'));
    const body = await c.req.json();
    
    if (isNaN(subdomainId)) {
      return c.json({ error: 'Invalid subdomain ID' }, 400);
    }
    
    // Check if subdomain exists
    const existingSubdomain = await db
      .select()
      .from(subdomains)
      .where(eq(subdomains.id, subdomainId))
      .limit(1);
    
    if (existingSubdomain.length === 0) {
      return c.json({ error: 'Subdomain not found' }, 404);
    }
    
    // Get domain info for validation
    const domain = await db
      .select()
      .from(domains)
      .where(eq(domains.id, existingSubdomain[0].domainId))
      .limit(1);
    
    const updateData: any = {};
    
    // Content field is readonly in updates
    if (body.content !== undefined) {
      return c.json({ error: 'Content field is readonly and cannot be updated' }, 400);
    }
    
    // Validate and update IP addresses if provided
    if (body.ipv4 !== undefined) {
      if (body.ipv4 && typeof body.ipv4 === 'string') {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (!ipv4Regex.test(body.ipv4)) {
          return c.json({ error: 'Invalid IPv4 address format' }, 400);
        }
        updateData.ipv4 = body.ipv4;
      } else {
        updateData.ipv4 = null;
      }
    }
    
    if (body.ipv6 !== undefined) {
      if (body.ipv6 && typeof body.ipv6 === 'string') {
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
        if (!ipv6Regex.test(body.ipv6)) {
          return c.json({ error: 'Invalid IPv6 address format' }, 400);
        }
        updateData.ipv6 = body.ipv6;
      } else {
        updateData.ipv6 = null;
      }
    }
    
    // Validate and update record IDs if provided
    if (body.ipv4RecordId !== undefined) {
      if (body.ipv4RecordId !== null && body.ipv4RecordId !== '' && body.ipv4RecordId !== undefined) {
        const recordId = parseInt(body.ipv4RecordId);
        if (isNaN(recordId) || recordId < 1) {
          return c.json({ error: 'IPv4 Record ID must be a positive integer or null' }, 400);
        }
        updateData.ipv4RecordId = recordId;
      } else {
        updateData.ipv4RecordId = null;
      }
    }
    
    if (body.ipv6RecordId !== undefined) {
      if (body.ipv6RecordId !== null && body.ipv6RecordId !== '' && body.ipv6RecordId !== undefined) {
        const recordId = parseInt(body.ipv6RecordId);
        if (isNaN(recordId) || recordId < 1) {
          return c.json({ error: 'IPv6 Record ID must be a positive integer or null' }, 400);
        }
        updateData.ipv6RecordId = recordId;
      } else {
        updateData.ipv6RecordId = null;
      }
    }
    
    // Validate and update enabled status if provided
    if (body.enabled !== undefined) {
      if (typeof body.enabled !== 'boolean') {
        return c.json({ error: 'Enabled must be a boolean value' }, 400);
      }
      updateData.enabled = body.enabled;
    }
    
    if (Object.keys(updateData).length === 0) {
      return c.json({ error: 'No valid fields to update' }, 400);
    }
    
    // Update subdomain
    await db
      .update(subdomains)
      .set(updateData)
      .where(eq(subdomains.id, subdomainId));
    
    // Fetch updated subdomain
    const updatedSubdomain = await db
      .select()
      .from(subdomains)
      .where(eq(subdomains.id, subdomainId))
      .limit(1);
    
    return c.json({ subdomain: updatedSubdomain[0] });
  } catch (error) {
    console.error('Error updating subdomain:', error);
    return c.json({ error: 'Failed to update subdomain' }, 500);
  }
});

app.delete('/api/admin/subdomains/:id', adminMiddleware, async (c) => {
  try {
    const subdomainId = parseInt(c.req.param('id'));
    
    if (isNaN(subdomainId)) {
      return c.json({ error: 'Invalid subdomain ID' }, 400);
    }
    
    // Check if subdomain exists
    const existingSubdomain = await db
      .select()
      .from(subdomains)
      .where(eq(subdomains.id, subdomainId))
      .limit(1);
    
    if (existingSubdomain.length === 0) {
      return c.json({ error: 'Subdomain not found' }, 404);
    }
    
    // Check if subdomain is enabled
    if (existingSubdomain[0].enabled) {
      return c.json({ error: 'Cannot delete enabled subdomains. Please disable the subdomain first.' }, 400);
    }
    
    // Delete subdomain
    await db.delete(subdomains).where(eq(subdomains.id, subdomainId));
    
    return c.json({ message: 'Subdomain deleted successfully' });
  } catch (error) {
    console.error('Error deleting subdomain:', error);
    return c.json({ error: 'Failed to delete subdomain' }, 500);
  }
});

app.post('/api/admin/subdomains/:id/sync-dns', adminMiddleware, async (c) => {
  try {
    const subdomainId = parseInt(c.req.param('id'));
    
    if (isNaN(subdomainId)) {
      return c.json({ error: 'Invalid subdomain ID' }, 400);
    }
    
    // Get subdomain with domain information
    const subdomainResult = await db
      .select({
        subdomain: subdomains,
        domain: domains
      })
      .from(subdomains)
      .innerJoin(domains, eq(subdomains.domainId, domains.id))
      .where(eq(subdomains.id, subdomainId))
      .limit(1);
    
    if (subdomainResult.length === 0) {
      return c.json({ error: 'Subdomain not found' }, 404);
    }
    
    const { subdomain, domain } = subdomainResult[0];
    
    if (!domain.bunnyId) {
      return c.json({ error: 'Domain is not linked to Bunny CDN' }, 400);
    }
    
    if (!subdomain.ipv4 && !subdomain.ipv6) {
      return c.json({ error: 'No IP addresses configured for this subdomain' }, 400);
    }
    
    const bunnyAccessKey = process.env.BUNNY_API_KEY;
    if (!bunnyAccessKey) {
      return c.json({ error: 'Bunny access key not configured' }, 500);
    }
    
    const updateData: any = {};
    
    // Handle IPv4 record
    if (subdomain.ipv4) {
      if (subdomain.ipv4RecordId) {
        // Update existing A record
        try {
          const updateUrl = `https://api.bunny.net/dnszone/${domain.bunnyId}/records/${subdomain.ipv4RecordId}`;
          const updateResponse = await fetch(updateUrl, {
            method: 'POST',
            headers: {
              'accept': 'application/json',
              'content-type': 'application/json',
              'AccessKey': bunnyAccessKey
            },
            body: JSON.stringify({
              Type: 0, // A record
              Ttl: 120,
              Value: subdomain.ipv4,
              Id: subdomain.ipv4RecordId,
              Name: subdomain.content
            })
          });
          
          if (!updateResponse.ok) {
            throw new Error(`Failed to update IPv4 record: ${updateResponse.statusText}`);
          }
        } catch (error) {
          console.error('Error updating IPv4 record:', error);
          return c.json({ error: 'Failed to update IPv4 record' }, 500);
        }
      } else {
        // Create new A record
        try {
          const createUrl = `https://api.bunny.net/dnszone/${domain.bunnyId}/records`;
          const createResponse = await fetch(createUrl, {
            method: 'PUT',
            headers: {
              'accept': 'application/json',
              'content-type': 'application/json',
              'AccessKey': bunnyAccessKey
            },
            body: JSON.stringify({
              Type: 0, // A record
              Ttl: 120,
              Value: subdomain.ipv4,
              Name: subdomain.content
            })
          });
          
          if (!createResponse.ok) {
            throw new Error(`Failed to create IPv4 record: ${createResponse.statusText}`);
          }
          
          const result = await createResponse.json();
          updateData.ipv4RecordId = result.Id;
        } catch (error) {
          console.error('Error creating IPv4 record:', error);
          return c.json({ error: 'Failed to create IPv4 record' }, 500);
        }
      }
    }
    
    // Handle IPv6 record
    if (subdomain.ipv6) {
      if (subdomain.ipv6RecordId) {
        // Update existing AAAA record
        try {
          const updateUrl = `https://api.bunny.net/dnszone/${domain.bunnyId}/records/${subdomain.ipv6RecordId}`;
          const updateResponse = await fetch(updateUrl, {
            method: 'POST',
            headers: {
              'accept': 'application/json',
              'content-type': 'application/json',
              'AccessKey': bunnyAccessKey
            },
            body: JSON.stringify({
              Type: 1, // AAAA record
              Ttl: 120,
              Value: subdomain.ipv6,
              Id: subdomain.ipv6RecordId,
              Name: subdomain.content
            })
          });
          
          if (!updateResponse.ok) {
            throw new Error(`Failed to update IPv6 record: ${updateResponse.statusText}`);
          }
        } catch (error) {
          console.error('Error updating IPv6 record:', error);
          return c.json({ error: 'Failed to update IPv6 record' }, 500);
        }
      } else {
        // Create new AAAA record
        try {
          const createUrl = `https://api.bunny.net/dnszone/${domain.bunnyId}/records`;
          const createResponse = await fetch(createUrl, {
            method: 'PUT',
            headers: {
              'accept': 'application/json',
              'content-type': 'application/json',
              'AccessKey': bunnyAccessKey
            },
            body: JSON.stringify({
              Type: 1, // AAAA record
              Ttl: 120,
              Value: subdomain.ipv6,
              Name: subdomain.content
            })
          });
          
          if (!createResponse.ok) {
            throw new Error(`Failed to create IPv6 record: ${createResponse.statusText}`);
          }
          
          const result = await createResponse.json();
          updateData.ipv6RecordId = result.Id;
        } catch (error) {
          console.error('Error creating IPv6 record:', error);
          return c.json({ error: 'Failed to create IPv6 record' }, 500);
        }
      }
    }
    
    // Update subdomain with new record IDs if any were created
    if (Object.keys(updateData).length > 0) {
      await db
        .update(subdomains)
        .set(updateData)
        .where(eq(subdomains.id, subdomainId));
    }
    
    return c.json({ message: 'DNS records synced successfully' });
  } catch (error) {
    console.error('Error syncing DNS records:', error);
    return c.json({ error: 'Failed to sync DNS records' }, 500);
  }
});

// User CRUD endpoints (Admin only)
app.post('/api/admin/users', adminMiddleware, async (c) => {
  try {
    const body = await c.req.json();
    
    // Input validation
    if (!body.name || typeof body.name !== 'string' || body.name.trim().length === 0) {
      return c.json({ error: 'Name is required and must be a non-empty string' }, 400);
    }
    
    if (!body.email || typeof body.email !== 'string') {
      return c.json({ error: 'Email is required' }, 400);
    }
    
    if (!body.password || typeof body.password !== 'string' || body.password.length < 8) {
      return c.json({ error: 'Password is required and must be at least 8 characters long' }, 400);
    }
    
    if (!body.role || !['admin', 'customer'].includes(body.role)) {
      return c.json({ error: 'Role must be either "admin" or "customer"' }, 400);
    }
    
    if (body.enabled !== undefined && typeof body.enabled !== 'boolean') {
      return c.json({ error: 'Enabled must be a boolean value' }, 400);
    }
    
    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(body.email)) {
      return c.json({ error: 'Invalid email format' }, 400);
    }
    
    // Sanitize inputs
    const name = body.name.trim();
    const email = body.email.trim().toLowerCase();
    const role = body.role;
    
    // Check if user already exists
    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);
    
    if (existingUser.length > 0) {
      return c.json({ error: 'User with this email already exists' }, 409);
    }
    
    // Hash password
    const hashedPassword = await hashPassword(body.password);
    
    // Create user
    const result = await db.insert(users).values({
      name,
      email,
      password: hashedPassword,
      role,
      enabled: body.enabled !== undefined ? body.enabled : false
    });
    
    return c.json({ 
      message: 'User created successfully',
      id: result.insertId 
    }, 201);
  } catch (error) {
    console.error('Error creating user:', error);
    return c.json({ error: 'Failed to create user' }, 500);
  }
});

app.put('/api/admin/users/:id', adminMiddleware, async (c) => {
  try {
    const userId = parseInt(c.req.param('id'));
    const body = await c.req.json();
    
    if (isNaN(userId)) {
      return c.json({ error: 'Invalid user ID' }, 400);
    }
    
    // Input validation
    if (!body.name || typeof body.name !== 'string' || body.name.trim().length === 0) {
      return c.json({ error: 'Name is required and must be a non-empty string' }, 400);
    }
    
    if (!body.email || typeof body.email !== 'string') {
      return c.json({ error: 'Email is required' }, 400);
    }
    
    if (!body.role || !['admin', 'customer'].includes(body.role)) {
      return c.json({ error: 'Role must be either "admin" or "customer"' }, 400);
    }
    
    if (body.enabled !== undefined && typeof body.enabled !== 'boolean') {
      return c.json({ error: 'Enabled must be a boolean value' }, 400);
    }
    
    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(body.email)) {
      return c.json({ error: 'Invalid email format' }, 400);
    }
    
    // Password validation (only if provided)
    if (body.password && (typeof body.password !== 'string' || body.password.length < 8)) {
      return c.json({ error: 'Password must be at least 8 characters long' }, 400);
    }
    
    // Check if user exists
    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.id, userId))
      .limit(1);
    
    if (existingUser.length === 0) {
      return c.json({ error: 'User not found' }, 404);
    }
    
    // Sanitize inputs
    const name = body.name.trim();
    const email = body.email.trim().toLowerCase();
    const role = body.role;
    
    // Check if email is already taken by another user
    const emailCheck = await db
      .select()
      .from(users)
      .where(and(eq(users.email, email), ne(users.id, userId)))
      .limit(1);
    
    if (emailCheck.length > 0) {
      return c.json({ error: 'Email is already taken by another user' }, 409);
    }
    
    // Business rule: Users cannot disable themselves
    const currentUserId = c.get('userId');
    if (userId === currentUserId && body.enabled === false) {
      return c.json({ error: 'You cannot disable your own account' }, 400);
    }
    
    // Prepare update data
    const updateData: any = {
      name,
      email,
      role,
      enabled: body.enabled !== undefined ? body.enabled : existingUser[0].enabled
    };
    
    // Add password to update if provided
    if (body.password) {
      updateData.password = await hashPassword(body.password);
    }
    
    // If user is being disabled, delete all their active tokens
    if (body.enabled === false && existingUser[0].enabled === true) {
      await db.delete(apiTokens).where(eq(apiTokens.userId, userId));
      console.log(`Deleted all tokens for disabled user: ${userId}`);
    }
    
    // Update user
    await db.update(users).set(updateData).where(eq(users.id, userId));
    
    return c.json({ message: 'User updated successfully' });
  } catch (error) {
    console.error('Error updating user:', error);
    return c.json({ error: 'Failed to update user' }, 500);
  }
});

app.delete('/api/admin/users/:id', adminMiddleware, async (c) => {
  try {
    const userId = parseInt(c.req.param('id'));
    const currentUserId = c.get('userId');
    
    if (isNaN(userId)) {
      return c.json({ error: 'Invalid user ID' }, 400);
    }
    
    // Prevent users from deleting themselves
    if (userId === currentUserId) {
      return c.json({ error: 'You cannot delete your own account' }, 400);
    }
    
    // Check if user exists
    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.id, userId))
      .limit(1);
    
    if (existingUser.length === 0) {
      return c.json({ error: 'User not found' }, 404);
    }
    
    // Business rule: Enabled users cannot be deleted
    if (existingUser[0].enabled) {
      return c.json({ error: 'Cannot delete enabled users. Please disable the user first.' }, 400);
    }
    
    // Check if user has any servers (prevent deletion if they do)
    const userServers = await db
      .select()
      .from(servers)
      .where(eq(servers.userId, userId))
      .limit(1);
    
    if (userServers.length > 0) {
      return c.json({ error: 'Cannot delete user with existing servers. Please delete their servers first.' }, 400);
    }
    
    // Delete user's API tokens first
    await db.delete(apiTokens).where(eq(apiTokens.userId, userId));
    
    // Delete user
    await db.delete(users).where(eq(users.id, userId));
    
    return c.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    return c.json({ error: 'Failed to delete user' }, 500);
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
const host = process.env.HOST || '0.0.0.0';

export default {
  port,
  host,
  fetch: app.fetch,
};