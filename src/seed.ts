import { db } from './db';
import { users, servers } from './db/schema';
import { hashPassword } from './auth';
import { eq } from 'drizzle-orm';

async function seed() {
  console.log('🌱 Seeding database...');
  
  try {
    // Check if admin user already exists
    const existingAdmin = await db.select().from(users).where(eq(users.email, 'admin@1.1'));
    
    let adminUser;
    if (existingAdmin.length > 0) {
      console.log('ℹ️  Admin user already exists');
      adminUser = existingAdmin;
    } else {
      // Create admin user
      const hashedPassword = await hashPassword('123');
      
      const result = await db.insert(users).values({
        name: 'Admin User',
        email: 'admin@1.1',
        password: hashedPassword,
        role: 'admin',
        enabled: true,
      });
      
      adminUser = await db.select().from(users).where(eq(users.email, 'admin@1.1'));
      
      console.log('✅ Admin user created successfully:');
      console.log('   Email: admin@1.1');
      console.log('   Password: 123');
      console.log('   Role: admin');
      console.log(`   ID: ${adminUser[0].id}`);
    }
    
    // Check if servers already exist for this admin
    const existingServers = await db.select().from(servers).where(eq(servers.userId, adminUser[0].id));
    
    if (existingServers.length > 0) {
      console.log('ℹ️  Servers already exist for admin user');
    } else {
      // Create 3 servers for admin user
      const serverData = [
        {
          name: 'Test Server',
          subdomain: 'test',
          status: 'running' as const,
          ram: 1024,
          storage: 4,
          cpuCores: 2,
          host: 'craftlite.de',
          serverVersion: '1.20.4',
          minecraftVersion: '1.20.4',
          userId: adminUser[0].id,
          lastActiveAt: new Date(),
        },
        {
          name: 'Development Server',
          subdomain: 'dev',
          status: 'running' as const,
          ram: 2048,
          storage: 8,
          cpuCores: 4,
          host: 'craftlite.de',
          serverVersion: '1.20.4',
          minecraftVersion: '1.20.4',
          userId: adminUser[0].id,
          lastActiveAt: new Date(),
        },
        {
          name: 'Staging Server',
          subdomain: 'staging',
          status: 'stopped' as const,
          ram: 512,
          storage: 2,
          cpuCores: 1,
          host: 'craftlite.de',
          serverVersion: '1.20.4',
          minecraftVersion: '1.20.4',
          userId: adminUser[0].id,
          stoppedAt: new Date(),
        }
      ];
      
      await db.insert(servers).values(serverData);
      const createdServers = await db.select().from(servers).where(eq(servers.userId, adminUser[0].id));
      
      console.log('✅ 3 servers created successfully:');
      createdServers.forEach((server, index) => {
        console.log(`   ${index + 1}. ${server.name} (${server.subdomain}.craftlite.de) - ${server.status}`);
      });
    }
    
  } catch (error) {
    console.error('❌ Error seeding database:', error);
    process.exit(1);
  }
}

// Only run if called directly (not imported)
if (import.meta.main) {
  seed().then(() => {
    console.log('🎉 Seeding completed');
    process.exit(0);
  }).catch((error) => {
    console.error('❌ Seeding failed:', error);
    process.exit(1);
  });
}

export { seed };