import express from 'express';

import {
  getUser,
  getUsers,
  updateMe,
  deleteMe
} from '../controllers/userController';
import { protect } from '../controllers/authController';

const router = express.Router();

router.route('/').get(getUsers);
router.route('/:id').get(getUser);
router.route('/updateMe').patch(protect, updateMe);
router.route('/deleteMe').delete(protect, deleteMe);

export default router;
