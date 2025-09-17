const express = require('express');
const AWS = require('aws-sdk');
const winston = require('winston');

// Enhanced logging configuration
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss'
    }),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      return JSON.stringify({
        timestamp,
        level,
        message,
        service: 'hello-app',
        environment: process.env.ENVIRONMENT || 'development',
        version: process.env.APP_VERSION || '1.0.0',
        requestId: meta.requestId || 'unknown',
        ...meta
      });
    })
  ),
  transports: [
    new winston.transports.Console({
      handleExceptions: true,
      handleRejections: true
    })
  ]
});

// request ID middleware
app.use((req, res, next) => {
  req.requestId = require('crypto').randomUUID();
  req.startTime = Date.now();
  logger.info('Incoming request', {
    requestId: req.requestId,
    method: req.method,
    url: req.url,
    userAgent: req.get('User-Agent'),
    ip: req.ip
  });
  next();
});

const app = express();
const port = process.env.PORT || 3000;

// Configure AWS SDK
AWS.config.update({
  region: process.env.AWS_REGION || 'us-east-1',
});

const ssm = new AWS.SSM();
const cloudwatch = new AWS.CloudWatch();

const startTime = Date.now(); // For uptime calculation

// Health check endpoint
app.get('/health', (req, res) => {
  const uptime = Date.now() - startTime;
  const healthCheck = {
    status: 'healthy',
    uptime: uptime,
    timestamp: new Date().toISOString(),
    version: process.env.APP_VERSION || '1.0.0',
    environment: process.env.ENVIRONMENT || 'development',
    requestId: req.requestId
  };

  logger.info('Health check requested', {
    requestId: req.requestId,
    uptime,
    responseTime: Date.now() - req.startTime
  });

  res.status(200).json(healthCheck);
});
// Main endpoint reading from Parameter Store
app.get('/', async (req, res) => {
  const startTime = Date.now();

  try {
    const params = {
      Names: [
        '/assignment-part-2/app/message',
        '/assignment-part-2/app/environment',
      ],
      withDecryption: true,
    };
    logger.info('Fetching parameters from Parameter Store ... ', {
      parameters: params.Names,
    });

    const result = await ssm.getParameters(params).promise();

    const config = {};
    result.Parameters.forEach((param) => {
      const key = param.Name.split('/').pop();
      config[key] = param.Value;
    });
    const responseTime = Date.now() - startTime;
    // Send custom metric to CloudWatch
    await sendMetricToCloudWatch('ResponseTime', responseTime, 'Milliseconds');
    await sendMetricToCloudWatch('RequestCount', 1, 'Count');

    const response = {
      message: config.message || 'Hello from DevOps Assignment!',
      environment: config.environment || 'development',
      timestamp: new Date().toISOString(),
      responseTime: `${responseTime}ms`,
      version: process.env.APP_VERSION || '1.0.0',
    };

    logger.info('Request processed successfully', {
      responseTime,
      parameters: Object.keys(config),
    });

    res.status(200).json(response);
  } catch (error) {
    const responseTime = Date.now() - startTime;

    logger.error('Error processing request', {
      error: error.message,
      stack: error.stack,
      responseTime,
    });

    // Send error metric to CloudWatch
    await sendMetricToCloudWatch('ErrorCount', 1, 'Count');

    res.status(500).json({
      error: 'Internal server error',
      timestamp: new Date().toISOString(),
      responseTime: `${responseTime}ms`,
    });
  }
});

// Function to send custom metrics to CloudWatch
async function sendMetricToCloudWatch(metricName, value, unit) {
  try {
    const params = {
      Namespace: 'DevOpsAssignment/Application',
      MetricData: [
        {
          MetricName: metricName,
          Value: value,
          Unit: unit,
          Timestamp: new Date(),
          Dimensions: [
            {
              Name: 'Environment',
              Value: process.env.ENVIRONMENT || 'development',
            },
            {
              Name: 'Service',
              Value: 'hello-app',
            },
          ],
        },
      ],
    };

    await cloudwatch.putMetricData(params).promise();
  } catch (error) {
    logger.warn('Failed to send metric to CloudWatch', {
      metric: metricName,
      error: error.message,
    });
  }
}

// Error handling middleware
app.use((error, req, res) => {
  logger.error('Unhandled error', {
    error: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
  });

  res.status(500).json({
    error: 'Internal server error',
    timestamp: new Date().toISOString(),
  });
});

// Start server
const server = app.listen(port, () => {
  logger.info('Application started', {
    port,
    environment: process.env.NODE_ENV || 'development',
    version: process.env.APP_VERSION || '1.0.0',
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Process terminated');
  });
});

module.exports = app;
