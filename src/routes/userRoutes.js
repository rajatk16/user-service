import express from 'express';

import { getUser, getUsers } from '../controllers/userController';

const router = express.Router();

router.route('/').get(getUsers);
router.route('/:id').get(getUser);

export default router;
