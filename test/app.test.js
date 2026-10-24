import assert from 'node:assert/strict';
import test from 'node:test';

import jwt from 'jsonwebtoken';
import request from 'supertest';

import { createApp, DEMO_LOGIN, DEMO_PASSWORD } from '../src/app.js';

const TEST_CONFIG = {
  port: 0,
  databasePath: ':memory:',
  jwtSecret: 'test-secret-that-is-long-enough-for-hs256-signing',
  jwtIssuer: 'hdu-is-lab1-secure-api',
  jwtAudience: 'hdu-is-lab1-client',
  jwtTtl: '15m',
  bcryptRounds: 4
};

async function makeTestApp() {
  return createApp({ config: TEST_CONFIG });
}

async function getAccessToken(app) {
  const response = await request(app)
    .post('/auth/login')
    .send({ login: DEMO_LOGIN, password: DEMO_PASSWORD });

  assert.equal(response.status, 200);
  assert.equal(typeof response.body.accessToken, 'string');
  return response.body.accessToken;
}

test('health endpoint is public', async (t) => {
  const { app, db } = await makeTestApp();
  t.after(() => db.close());

  const response = await request(app).get('/health');

  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { status: 'ok' });
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
});

test('login returns a JWT without leaking the password hash', async (t) => {
  const { app, db } = await makeTestApp();
  t.after(() => db.close());

  const response = await request(app)
    .post('/auth/login')
    .send({ login: DEMO_LOGIN, password: DEMO_PASSWORD });

  assert.equal(response.status, 200);
  assert.equal(response.body.tokenType, 'Bearer');
  assert.equal(response.body.user.login, DEMO_LOGIN);
  assert.equal(JSON.stringify(response.body).includes('password_hash'), false);
});

test('SQL injection in the login field does not bypass authentication', async (t) => {
  const { app, db } = await makeTestApp();
  t.after(() => db.close());

  const response = await request(app)
    .post('/auth/login')
    .send({ login: "' OR 1=1 --", password: 'anything' });

  assert.equal(response.status, 401);
  assert.equal(response.body.accessToken, undefined);
});

test('protected data endpoint rejects requests without a token', async (t) => {
  const { app, db } = await makeTestApp();
  t.after(() => db.close());

  const response = await request(app).get('/api/data');

  assert.equal(response.status, 401);
  assert.deepEqual(response.body, { error: 'Authentication required' });
});

test('protected data endpoint rejects invalid and wrongly signed JWTs', async (t) => {
  const { app, db } = await makeTestApp();
  t.after(() => db.close());

  const malformed = await request(app)
    .get('/api/data')
    .set('Authorization', 'Bearer not-a-jwt');
  assert.equal(malformed.status, 401);

  const wrongSecretToken = jwt.sign(
    { login: DEMO_LOGIN },
    'a-different-secret-that-is-at-least-32-characters',
    {
      algorithm: 'HS256',
      audience: TEST_CONFIG.jwtAudience,
      issuer: TEST_CONFIG.jwtIssuer,
      subject: '1',
      expiresIn: '15m'
    }
  );
  const forged = await request(app)
    .get('/api/data')
    .set('Authorization', `Bearer ${wrongSecretToken}`);
  assert.equal(forged.status, 401);
});

test('authenticated users can read data', async (t) => {
  const { app, db } = await makeTestApp();
  t.after(() => db.close());

  const token = await getAccessToken(app);
  const response = await request(app)
    .get('/api/data')
    .set('Authorization', `Bearer ${token}`);

  assert.equal(response.status, 200);
  assert.equal(Array.isArray(response.body.data), true);
  assert.equal(response.body.data.length, 2);
});

test('creating a post escapes user-controlled HTML in the response', async (t) => {
  const { app, db } = await makeTestApp();
  t.after(() => db.close());

  const token = await getAccessToken(app);
  const created = await request(app)
    .post('/api/posts')
    .set('Authorization', `Bearer ${token}`)
    .send({
      title: '<script>alert("title")</script>',
      body: '<img src=x onerror=alert("body")>'
    });

  assert.equal(created.status, 201);
  assert.equal(created.body.post.title, '&lt;script&gt;alert(&quot;title&quot;)&lt;/script&gt;');
  assert.equal(created.body.post.body, '&lt;img src=x onerror=alert(&quot;body&quot;)&gt;');

  const data = await request(app)
    .get('/api/data')
    .set('Authorization', `Bearer ${token}`);
  assert.equal(data.status, 200);
  assert.equal(JSON.stringify(data.body).includes('<script>'), false);
  assert.equal(JSON.stringify(data.body).includes('<img'), false);
});

test('post endpoint validates input and requires authentication', async (t) => {
  const { app, db } = await makeTestApp();
  t.after(() => db.close());

  const unauthenticated = await request(app)
    .post('/api/posts')
    .send({ title: 'No token', body: 'This should fail' });
  assert.equal(unauthenticated.status, 401);

  const token = await getAccessToken(app);
  const invalid = await request(app)
    .post('/api/posts')
    .set('Authorization', `Bearer ${token}`)
    .send({ title: '', body: 'Missing title' });
  assert.equal(invalid.status, 400);
});
