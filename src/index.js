/* eslint-disable import/first */
import mongoose from 'mongoose';

process.on('uncaughtException', err => {
  console.log('UNHANDLED EXCEPTION!');
  console.log(err);
  process.exit(1);
});

import app from './app';

const DB_URI = process.env.DATABASE_URI.replace(
  '<PASSWORD>',
  process.env.DATABASE_PASSWORD
);

console.log(typeof process.env.JWT_EXPIRES_IN);

mongoose
  .connect(DB_URI, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
    useUnifiedTopology: true
  })
  .then(() => console.log('DB Connection Successful'));

const port = process.env.PORT || 3000;

const server = app.listen(port, () => {
  console.log(
    `User Service running in ${process.env.NODE_ENV} mode on PORT ${process.env.PORT}`
  );
});

process.on('unhandledRejection', err => {
  console.log('UNHANDLED REJECTION');
  console.log(err);
  server.close(() => {
    process.exit(1);
  });
});
