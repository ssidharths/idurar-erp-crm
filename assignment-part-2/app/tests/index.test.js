const request = require('supertest');
const app = require('../src/index');

// Mock AWS SDK
jest.mock('aws-sdk', () => {
  const mockSSM = {
    getParameters: jest.fn(() => ({
      promise: () =>
        Promise.resolve({
          Parameters: [
            {
              Name: '/assignment-part-2/app/message',
              Value: 'Hello from Test!',
            },
            {
              Name: '/assignment-part-2/app/environment',
              Value: 'test',
            },
          ],
        }),
    })),
  };

  const mockCloudWatch = {
    putMetricData: jest.fn(() => ({
      promise: () => Promise.resolve({}),
    })),
  };

  return {
    SSM: jest.fn(() => mockSSM),
    CloudWatch: jest.fn(() => mockCloudWatch),
    config: {
      update: jest.fn(),
    },
  };
});

describe('Hello World Microservice', () => {
  describe('GET /health', () => {
    it('should return health status', async () => {
      const response = await request(app).get('/health');

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('status', 'healthy');
      expect(response.body).toHaveProperty('uptime');
      expect(response.body).toHaveProperty('timestamp');
      expect(response.body).toHaveProperty('version');
    });
  });

  describe('GET /', () => {
    it('should return message from Parameter Store', async () => {
      const response = await request(app).get('/');

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('message', 'Hello from Test!');
      expect(response.body).toHaveProperty('environment', 'test');
      expect(response.body).toHaveProperty('timestamp');
      expect(response.body).toHaveProperty('responseTime');
      expect(response.body).toHaveProperty('version');
    });

    it('should handle Parameter Store errors gracefully', async () => {
      // Mock SSM to throw an error
      const AWS = require('aws-sdk');
      const mockSSM = new AWS.SSM();
      mockSSM.getParameters.mockImplementationOnce(() => ({
        promise: () => Promise.reject(new Error('Parameter Store error')),
      }));

      const response = await request(app).get('/');

      expect(response.status).toBe(500);
      expect(response.body).toHaveProperty('error', 'Internal server error');
      expect(response.body).toHaveProperty('timestamp');
    });
  });

  afterAll((done) => {
    // Close server after tests
    if (app.server) {
      app.server.close(done);
    } else {
      done();
    }
  });
});
