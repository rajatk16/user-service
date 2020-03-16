import User from '../models/User';
import catchAsync from '../utils/catchAsync';
import AppError from '../utils/AppError';

export const getUsers = catchAsync(async (req, res, next) => {
  const users = await User.find();

  res.status(200).json({
    message: 'Success',
    data: {
      users
    }
  });
});

export const getUser = catchAsync(async (req, res, next) => {
  const foundUser = await User.findById(req.params.id);

  if (!foundUser) {
    return next(new AppError('User not found', 404));
  }

  res.status(200).json({
    status: 'Success',
    data: {
      user: foundUser
    }
  });
});
