import { Router } from 'express';
import * as moduleController from '../controllers/module.controller';
import { authenticate, authorize } from '../middlewares/auth.middleware';

const router = Router();

/**
 * @swagger
 * tags:
 *   name: Modules
 *   description: Module and access management
 */

/**
 * @swagger
 * /modules:
 *   get:
 *     summary: Get all modules
 *     tags: [Modules]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of modules fetched successfully
 */
router.get('/', authenticate, moduleController.getModules);

/**
 * @swagger
 * /modules:
 *   post:
 *     summary: Create a new module
 *     tags: [Modules]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - code
 *               - name
 *             properties:
 *               code:
 *                 type: string
 *               name:
 *                 type: string
 *               description:
 *                 type: string
 *               icon:
 *                 type: string
 *               path:
 *                 type: string
 *               parentId:
 *                 type: string
 *               order:
 *                 type: number
 *     responses:
 *       201:
 *         description: Module created successful
 */
router.post('/', authenticate, authorize(['SUPERADMIN']), moduleController.createModule);

/**
 * @swagger
 * /modules/{id}:
 *   put:
 *     summary: Update an existing module
 *     tags: [Modules]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               description:
 *                 type: string
 *               icon:
 *                 type: string
 *               path:
 *                 type: string
 *               order:
 *                 type: number
 *               isActive:
 *                 type: boolean
 *               isVisible:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Module updated successfully
 */
router.put('/:id', authenticate, authorize(['SUPERADMIN']), moduleController.updateModule);

/**
 * @swagger
 * /modules/{id}:
 *   delete:
 *     summary: Delete a module
 *     tags: [Modules]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Module deleted successfully
 */
router.delete('/:id', authenticate, authorize(['SUPERADMIN']), moduleController.deleteModule);

export default router;
