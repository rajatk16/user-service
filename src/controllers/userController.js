import User from '../models/User';
import catchAsync from '../utils/catchAsync';
import AppError from '../utils/AppError';

const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach(el => {
    if (allowedFields.includes(el)) {
      newObj[el] = obj[el];
    }
  });
  return newObj;
};

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

export const updateMe = catchAsync(async (req, res, next) => {
  // Create error tries to update password
  if (req.body.password || req.body.passwordConfirm) {
    return next(new AppError('User cannot update their password here', 400));
  }
  // Update user document
  const filteredBody = filterObj(req.body, 'firstName', 'lastName', 'email');
  const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
    new: true,
    runValidators: true
  });
  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser
    }
  });
});

export const deleteMe = catchAsync(async (req, res, next) => {
  await User.findByIdAndUpdate(req.user.id, { active: false });

  res.status(204).json({
    status: 'Success',
    data: null
  });
});
