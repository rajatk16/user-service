import express from 'express';
import morgan from 'morgan';

import AppError from './utils/AppError';
import globalErrorController from './utils/globalErrorController';
import authRouter from './routes/authRoutes';
import userRouter from './routes/userRoutes';

const app = express();

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}
app.use(express.json());
app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  next();
});

app.use('/api/v1/auth', authRouter);
app.use('/api/v1/users', userRouter);

app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorController);

export default app;
