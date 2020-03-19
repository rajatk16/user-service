import { promisify } from 'util';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import AppError from '../utils/AppError';
import catchAsync from '../utils/catchAsync';
import User from '../models/User';
import sendEmail from '../utils/sendMail';

// Create a JWT containing User's ID.
const signToken = id => {
  return jwt.sign(
    {
      id
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES_IN
    }
  );
};

// Call Sign Token to create JWT and send it as response, along with user details
const createSendToken = (user, status, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    secure: false,
    httpOnly: true
  };

  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

  res.cookie('jwt', token, cookieOptions);

  user.password = undefined;

  res.status(status).json({
    message: 'Success',
    token,
    data: {
      user
    }
  });
};

// Controller to CREATE a User's record in DB
export const signUp = catchAsync(async (req, res, next) => {
  // Only take firstName, lastName, email, and password from request body
  const { firstName, lastName, email, password, passwordConfirm } = req.body;
  const newUser = await User.create({
    firstName,
    lastName,
    email,
    password,
    passwordConfirm
  });

  createSendToken(newUser, 201, res);
});

// Controller to login the user
export const login = catchAsync(async (req, res, next) => {
  // Take only email and password from request body
  const { email, password } = req.body;
  // If email or password not found, throw error
  if (!email || !password) {
    return next(new AppError('Please provide an email and password', 400));
  }

  // Find the user in DB using email. Also get the stored password
  const user = await User.findOne({
    email
  }).select('+password');

  // Check if password entered matches with stored password
  const correct = await user.correctPassword(password, user.password);

  // If User not found in DB or if entered password is incorrect, throw error
  if (!user || !correct) {
    return next(new AppError('Incorrect email or password'), 401);
  }

  createSendToken(user, 200, res);
});

// Check if user is logged in
export const protect = catchAsync(async (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }
  // If no token found in Request => No User has logged in
  if (!token) {
    return next(new AppError('You are not logged in! Please log in'), 401);
  }
  // Get the secret from the token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // Find the user from the db that matches token's id
  const freshUser = await User.findById(decoded.id);
  // If no user found, throw error
  if (!freshUser)
    return next(
      new AppError('The User belonging to this token no longer exists', 401)
    );
  // If user's password was changed recently. Login again
  if (freshUser.changedPasswordAfter(decoded.iat)) {
    return next(
      new AppError('User recently changed password! Please log in again.', 401)
    );
  }
  // Save user details in request
  req.user = freshUser;
  next();
});

// Restrict a role is allowed to go to a route
export const restrictTo = (...roles) => {
  return catchAsync(async (req, res, next) => {
    // If user's role does not match with allowed roles, throw error
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', 403)
      );
    }
    next();
  });
};

// If password forgotten, send email to user with reset link
export const forgotPassword = catchAsync(async (req, res, next) => {
  const user = await User.findOne({
    email: req.body.email
  });

  if (!user) {
    return next(new AppError('There is no user with that email address', 404));
  }

  const resetToken = user.createPasswordResetToken();

  await user.save({
    validateBeforeSave: false
  });

  const resetURL = `${req.protocol}://${req.get(
    'host'
  )}/api/v1/auth/resetPassword/${resetToken}`;

  const message = `
    Forgot your password? Please submit a PATCH request with your new password and passwordConfirm to: ${resetURL}.
    \n
    If you didn't forget your password, please ignore this email
  `;
  try {
    await sendEmail({
      email: user.email,
      subject: 'Your password reset link is here (valid for 10 mins!)',
      message
    });

    res.status(200).json({
      status: 'Success',
      message: "Token sent to user's email"
    });
  } catch (error) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save({ validateBeforeSave: false });
    return next(
      new AppError(
        'There was an error while sending the email. Please try again later',
        500
      )
    );
  }
});

// Reset the password
export const resetPassword = catchAsync(async (req, res, next) => {
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: {
      $gt: Date.now()
    }
  });

  if (!user) return next(new AppError('Token is invalid or expired', 400));

  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  createSendToken(user, 200, res);
});

export const updatePassword = catchAsync(async (req, res, next) => {
  // Get user from the collection
  const user = await User.findById(req.user.id).select('+password');

  if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) {
    return next(new AppError('Your current password is wrong'));
  }
  // Check if password is correct
  // If yes then update the password
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  await user.save();
  // Log user in, and send JWT
  createSendToken(user, 200, res);
});
