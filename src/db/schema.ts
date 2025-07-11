import { sqliteTable, text, integer } from 'drizzle-orm/sqlite-core';

export const users = sqliteTable('users', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  name: text('name').notNull(),
  email: text('email').unique().notNull(),
  password: text('password').notNull(),
  role: text('role', { enum: ['admin', 'customer'] }).notNull().default('customer'),
  createdAt: integer('created_at', { mode: 'timestamp' }).$defaultFn(() => new Date()),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).$defaultFn(() => new Date()),
});

export const apiTokens = sqliteTable('api_tokens', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  token: text('token').notNull().unique(),
  userId: integer('user_id').references(() => users.id).notNull(),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }).$defaultFn(() => new Date()),
});

export const posts = sqliteTable('posts', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  title: text('title').notNull(),
  content: text('content'),
  authorId: integer('author_id').references(() => users.id),
  createdAt: integer('created_at', { mode: 'timestamp' }).$defaultFn(() => new Date()),
});

export const servers = sqliteTable('servers', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  name: text('name').notNull(),
  subdomain: text('subdomain').unique().notNull(),
  status: text('status', { enum: ['starting', 'running', 'stopping', 'stopped', 'error'] }).notNull().default('stopped'),
  ram: integer('ram').notNull(), // MB
  storage: integer('storage').notNull(), // GB
  cpuCores: integer('cpu_cores').notNull(),
  host: text('host').notNull(),
  serverVersion: text('server_version').notNull(),
  minecraftVersion: text('minecraft_version').notNull(),
  userId: integer('user_id').references(() => users.id).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }).$defaultFn(() => new Date()),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).$defaultFn(() => new Date()),
  deletedAt: integer('deleted_at', { mode: 'timestamp' }),
  stoppedAt: integer('stopped_at', { mode: 'timestamp' }),
  lastActiveAt: integer('last_active_at', { mode: 'timestamp' }),
});