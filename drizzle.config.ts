import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  out: './drizzle',
  schema: './src/db/schema.ts',
  dialect: 'mysql',
  dbCredentials: {
    host: process.env.DATABASE_HOST || 'localhost',
    port: parseInt(process.env.DATABASE_PORT || '3306'),
    user: process.env.DATABASE_USER || 'noxomix',
    password: process.env.DATABASE_PASSWORD || 'noxomix_secure_password_2024',
    database: process.env.DATABASE_NAME || 'noxomix',
  },
});