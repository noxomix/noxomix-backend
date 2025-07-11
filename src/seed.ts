import { db } from './db';
import { users } from './db/schema';
import { hashPassword } from './auth';
import { eq } from 'drizzle-orm';

async function seed() {
  console.log('🌱 Seeding database...');
  
  try {
    // Check if admin user already exists
    const existingAdmin = await db.select().from(users).where(eq(users.email, 'admin@cheapsheep.com'));
    
    if (existingAdmin.length > 0) {
      console.log('ℹ️  Admin user already exists');
      return;
    }
    
    // Create admin user
    const hashedPassword = await hashPassword('admin123');
    
    const adminUser = await db.insert(users).values({
      name: 'Admin User',
      email: 'admin@cheapsheep.com',
      password: hashedPassword,
      role: 'admin',
    }).returning();
    
    console.log('✅ Admin user created successfully:');
    console.log('   Email: admin@cheapsheep.com');
    console.log('   Password: admin123');
    console.log('   Role: admin');
    console.log(`   ID: ${adminUser[0].id}`);
    
  } catch (error) {
    console.error('❌ Error seeding database:', error);
    process.exit(1);
  }
}

// Run seeder
seed().then(() => {
  console.log('🎉 Seeding completed');
  process.exit(0);
}).catch((error) => {
  console.error('❌ Seeding failed:', error);
  process.exit(1);
});