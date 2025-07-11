import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { db } from './db';
import { users, apiTokens } from './db/schema';
import { eq } from 'drizzle-orm';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function generateToken(userId: number): string {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
}

export function verifyToken(token: string): { userId: number } | null {
  try {
    return jwt.verify(token, JWT_SECRET) as { userId: number };
  } catch {
    return null;
  }
}

export async function createApiToken(userId: number): Promise<string> {
  const token = generateToken(userId);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
  
  await db.insert(apiTokens).values({
    token,
    userId,
    expiresAt,
  });
  
  return token;
}

export async function validateApiToken(token: string): Promise<{ userId: number } | null> {
  const decoded = verifyToken(token);
  if (!decoded) return null;
  
  const apiToken = await db.select().from(apiTokens)
    .where(eq(apiTokens.token, token))
    .limit(1);
  
  if (apiToken.length === 0 || apiToken[0].expiresAt < new Date()) {
    return null;
  }
  
  return { userId: decoded.userId };
}

export async function validateAdminToken(token: string): Promise<{ userId: number; isAdmin: boolean } | null> {
  const decoded = verifyToken(token);
  if (!decoded) return null;
  
  const apiToken = await db.select().from(apiTokens)
    .where(eq(apiTokens.token, token))
    .limit(1);
  
  if (apiToken.length === 0 || apiToken[0].expiresAt < new Date()) {
    return null;
  }
  
  // Check if user is admin
  const user = await db.select().from(users)
    .where(eq(users.id, decoded.userId))
    .limit(1);
  
  if (user.length === 0 || user[0].role !== 'admin') {
    return null;
  }
  
  return { userId: decoded.userId, isAdmin: true };
}