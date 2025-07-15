import { mysqlTable, varchar, int, timestamp, text, mysqlEnum, boolean } from 'drizzle-orm/mysql-core';

export const users = mysqlTable('users', {
  id: int('id').primaryKey().autoincrement(),
  name: varchar('name', { length: 255 }).notNull(),
  email: varchar('email', { length: 255 }).unique().notNull(),
  password: varchar('password', { length: 255 }).notNull(),
  role: mysqlEnum('role', ['admin', 'customer']).notNull().default('customer'),
  enabled: boolean('enabled').notNull().default(false),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow().onUpdateNow(),
});

export const apiTokens = mysqlTable('api_tokens', {
  id: int('id').primaryKey().autoincrement(),
  token: varchar('token', { length: 255 }).notNull().unique(),
  userId: int('user_id').references(() => users.id).notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').defaultNow(),
});

export const posts = mysqlTable('posts', {
  id: int('id').primaryKey().autoincrement(),
  title: varchar('title', { length: 255 }).notNull(),
  content: text('content'),
  authorId: int('author_id').references(() => users.id),
  createdAt: timestamp('created_at').defaultNow(),
});

export const servers = mysqlTable('servers', {
  id: int('id').primaryKey().autoincrement(),
  name: varchar('name', { length: 255 }).notNull(),
  subdomain: varchar('subdomain', { length: 255 }).unique().notNull(),
  status: mysqlEnum('status', ['starting', 'running', 'stopping', 'stopped', 'error']).notNull().default('stopped'),
  ram: int('ram').notNull(), // MB
  storage: int('storage').notNull(), // GB
  cpuCores: int('cpu_cores').notNull(),
  host: varchar('host', { length: 255 }).notNull(),
  serverVersion: varchar('server_version', { length: 50 }).notNull(),
  minecraftVersion: varchar('minecraft_version', { length: 50 }).notNull(),
  userId: int('user_id').references(() => users.id).notNull(),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow().onUpdateNow(),
  deletedAt: timestamp('deleted_at'),
  stoppedAt: timestamp('stopped_at'),
  lastActiveAt: timestamp('last_active_at'),
});

export const domains = mysqlTable('domains', {
  id: int('id').primaryKey().autoincrement(),
  name: varchar('name', { length: 255 }).notNull().unique(),
  bunnyId: int('bunny_id'),
  enabled: mysqlEnum('enabled', ['enabled', 'disabled']).notNull().default('enabled'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow().onUpdateNow(),
});

export const subdomains = mysqlTable('subdomains', {
  id: int('id').primaryKey().autoincrement(),
  domainId: int('domain_id').references(() => domains.id).notNull(),
  content: varchar('content', { length: 255 }).notNull().unique(),
  ipv4: varchar('ipv4', { length: 45 }),
  ipv6: varchar('ipv6', { length: 45 }),
  ipv4RecordId: int('ipv4_record_id'),
  ipv6RecordId: int('ipv6_record_id'),
  enabled: boolean('enabled').notNull().default(true),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow().onUpdateNow(),
});