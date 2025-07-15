import mysql from 'mysql2/promise';
import { drizzle } from 'drizzle-orm/mysql2';
import * as schema from './db/schema';
import { seed } from './seed';

async function fresh() {
  console.log("🔄 Fresh database setup for Noxomix...");
  console.log("⚠️  WARNING: This will DELETE ALL DATA in the database!");
  console.log("Press Ctrl+C to cancel, or Enter to continue...");
  
  // Wait for Enter key
  if (process.stdin.setRawMode) {
    process.stdin.setRawMode(true);
  }
  process.stdin.resume();
  await new Promise((resolve) => {
    process.stdin.once('data', (data) => {
      const key = data.toString();
      if (key === '\r' || key === '\n') {
        if (process.stdin.setRawMode) {
          process.stdin.setRawMode(false);
        }
        process.stdin.pause();
        resolve(undefined);
      } else if (key === '\u0003') { // Ctrl+C
        console.log('\nCancelled.');
        process.exit(0);
      }
    });
  });
  
  const config = {
    host: process.env.DATABASE_HOST || 'localhost',
    port: parseInt(process.env.DATABASE_PORT || '3306'),
    user: process.env.DATABASE_USER || 'noxomix',
    password: process.env.DATABASE_PASSWORD || 'noxomix_secure_password_2024',
    database: process.env.DATABASE_NAME || 'noxomix',
  };

  console.log("🗑️  Dropping and recreating database...");
  
  // Connect without database to drop/create
  const connection = await mysql.createConnection({
    host: config.host,
    port: config.port,
    user: config.user,
    password: config.password,
  });

  try {
    // Drop database if exists
    await connection.execute(`DROP DATABASE IF EXISTS ${config.database}`);
    console.log("📦 Database dropped");
    
    // Create database
    await connection.execute(`CREATE DATABASE ${config.database} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    console.log("✨ Database created");
    
    await connection.end();
    
    // Now connect with database selected
    const pool = mysql.createPool(config);
    const db = drizzle(pool, { schema, mode: 'default' });
    
    console.log("📊 Running migrations...");
    // Run Drizzle push
    const { execSync } = require('child_process');
    execSync('bun drizzle-kit push', { stdio: 'inherit' });
    
    // Run seed directly
    await seed();
    
    await pool.end();
    
    console.log("🎉 Fresh database setup complete!");
    process.exit(0);
  } catch (error) {
    console.error("❌ Error:", error);
    process.exit(1);
  }
}

fresh();