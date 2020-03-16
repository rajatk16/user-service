/* eslint-disable consistent-return */
/* eslint-disable object-shorthand */
/* eslint-disable func-names */
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import validator from 'validator';
import crypto from 'crypto';

const UserSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, 'Please provide your first name']
  },
  lastName: {
    type: String,
    required: [true, 'Please provide your last name']
  },
  email: {
    type: String,
    required: [true, 'Please provide your email address'],
    unique: [true, 'User with this email already exists'],
    lowercase: true,
    validate: [validator.isEmail, 'This is not a valid email']
  },
  photo: {
    type: String
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  password: {
    type: String,
    required: [true, 'Please enter a password'],
    minlength: 8,
    select: false
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please enter a password'],
    validate: {
      validator: function(el) {
        return el === this.password;
      },
      message: 'Does not match with Password'
    }
  },
  passwordResetToken: {
    type: String
  },
  passwordResetExpires: {
    type: Date
  },
  createdAt: {
    type: Date,
    default: Date.now()
  },
  updatedAt: {
    type: Date
  }
});

UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.passwordConfirm = undefined;
  next();
});

UserSchema.pre('update', async function(next) {
  this.updatedAt = Date.now();
  next();
});

UserSchema.methods.correctPassword = async function(
  candidatePassword,
  userPassword
) {
  const result = await bcrypt.compare(candidatePassword, userPassword);
  return result;
};

UserSchema.methods.changedPasswordAfter = async function(JWTTimestamp) {
  if (this.changedPasswordAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

UserSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

const User = mongoose.model('User', UserSchema);

export default User;
