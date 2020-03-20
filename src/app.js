import express from 'express';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import mongoSanitize from 'express-mongo-sanitize';
import xss from 'xss-clean';
import hpp from 'hpp';

import AppError from './utils/AppError';
import globalErrorController from './utils/globalErrorController';
import authRouter from './routes/authRoutes';
import userRouter from './routes/userRoutes';

const app = express();

// Middlewares
// Set Security HTTP Headers
app.use(helmet());

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Limit API requests to 100 per hour from each IP
const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: 'Too many requests from this IP, please try again in an hour'
});
app.use('/api', limiter);

// Body Parser
app.use(
  express.json({
    limit: '10kb'
  })
);

// Data Sanitization against NoSQL Query Injection
app.use(mongoSanitize());

// Against XSS
app.use(xss());

// Prevent Parameter Pollution
app.use(hpp());

// Set Request Time on Request
app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  next();
});

// Routes
app.use('/api/v1/auth', authRouter);
app.use('/api/v1/users', userRouter);

app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorController);

export default app;
