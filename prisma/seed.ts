import { PrismaClient, LoginStatus } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
    console.log('Seed started...');

    // 1. Create Roles
    const superadminRole = await prisma.role.upsert({
        where: { code: 'SUPERADMIN' },
        update: {},
        create: {
            code: 'SUPERADMIN',
            name: 'Super Administrator',
            description: 'Full access to all modules',
            level: 100,
            isSystem: true,
        },
    });

    const adminRole = await prisma.role.upsert({
        where: { code: 'ADMIN' },
        update: {},
        create: {
            code: 'ADMIN',
            name: 'Administrator',
            description: 'General administrative access',
            level: 80,
        },
    });

    console.log('Roles created.');

    // 2. Create Modules
    const modules = [
        { code: 'DASHBOARD', name: 'Dashboard', icon: 'LayoutDashboard', path: '/dashboard', order: 1 },
        { code: 'ROLES', name: 'Role Management', icon: 'Shield', path: '/master/roles', order: 2 },
        { code: 'MODULES', name: 'Module Management', icon: 'Package', path: '/master/modules', order: 3 },
        { code: 'USERS', name: 'User Management', icon: 'Users', path: '/master/users', order: 4 },
    ];

    for (const m of modules) {
        await prisma.module.upsert({
            where: { code: m.code },
            update: m,
            create: m,
        });
    }

    const createdModules = await prisma.module.findMany();
    console.log('Modules created.');

    // 3. Setup Superadmin Access to all modules
    for (const mod of createdModules) {
        await prisma.moduleAccess.upsert({
            where: {
                roleId_moduleId: {
                    roleId: superadminRole.id,
                    moduleId: mod.id,
                },
            },
            update: {
                canView: true,
                canCreate: true,
                canUpdate: true,
                canDelete: true,
                canViewAll: true,
                canDownload: true,
                canApprove: true,
            },
            create: {
                roleId: superadminRole.id,
                moduleId: mod.id,
                canView: true,
                canCreate: true,
                canUpdate: true,
                canDelete: true,
                canViewAll: true,
                canDownload: true,
                canApprove: true,
            },
        });
    }

    console.log('Module access for Superadmin configured.');

    // 4. Create Superadmin User
    const hashedPassword = await bcrypt.hash('admin123', 12);
    const adminUser = await prisma.user.upsert({
        where: { username: 'admin' },
        update: {},
        create: {
            username: 'admin',
            email: 'admin@system.com',
            password: hashedPassword,
            name: 'System Administrator',
            isEmailVerified: true,
            mustChangePassword: false,
        },
    });

    // Assign role to user
    await prisma.userRole.upsert({
        where: {
            userId_roleId: {
                userId: adminUser.id,
                roleId: superadminRole.id,
            },
        },
        update: {},
        create: {
            userId: adminUser.id,
            roleId: superadminRole.id,
        },
    });

    console.log('Superadmin user created (admin/admin123).');
    console.log('Seed completed successfully.');
}

main()
    .catch((e) => {
        console.error(e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
