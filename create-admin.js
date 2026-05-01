const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs'); 
const prisma = new PrismaClient();

async function main() {
  const password = 'password123';
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  console.log('🚀 Creating Admin User via Prisma...');

  try {
    const admin = await prisma.user.upsert({
      where: { username: 'admin' },
      update: {
        password: hashedPassword,
        isActive: true
      },
      create: {
        id: 'user-admin-001',
        username: 'admin',
        email: 'admin@sekolah.com',
        password: hashedPassword,
        name: 'Super Admin',
        isActive: true,
        mustChangePassword: false
      }
    });

    console.log('✅ Admin user created/updated successfully!');
    console.log('Username: admin');
    console.log('Password: password123');
  } catch (error) {
    console.error('❌ Error:', error.message);
  } finally {
    await prisma.$disconnect();
  }
}

main();
