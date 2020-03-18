import express from 'express';

import {
  signUp,
  login,
  forgotPassword,
  resetPassword,
  updatePassword,
  protect
} from '../controllers/authController';

const router = express.Router();

router.route('/signup').post(signUp);
router.route('/login').post(login);
router.route('/forgotPassword').post(forgotPassword);
router.route('/resetPassword/:token').patch(resetPassword);
router.route('/updateMyPassword').patch(protect, updatePassword);
export default router;
