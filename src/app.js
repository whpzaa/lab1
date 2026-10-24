import bcrypt from 'bcryptjs';
import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

import { loadConfig } from './config.js';
import { openDatabase } from './db.js';
import {
  createAuthenticateMiddleware,
  serializePost,
  serializeUser,
  signAccessToken,
  validateCredentials,
  validatePost
} from './security.js';

const DEMO_LOGIN = 'alice';
const DEMO_PASSWORD = 'CorrectHorseBatteryStaple!42';

async function seedDatabase(db, bcryptRounds) {
  const existingUsers = db.prepare('SELECT COUNT(*) AS count FROM users').get();
  if (existingUsers.count > 0) {
    return;
  }

  const passwordHash = await bcrypt.hash(DEMO_PASSWORD, bcryptRounds);
  const insertUser = db.prepare(
    'INSERT INTO users (login, password_hash, display_name) VALUES (?, ?, ?)'
  );
  const insertPost = db.prepare(
    'INSERT INTO posts (author_id, title, body) VALUES (?, ?, ?)'
  );

  db.exec('BEGIN');
  try {
    const result = insertUser.run(DEMO_LOGIN, passwordHash, 'Alice Demo');
    insertPost.run(
      result.lastInsertRowid,
      'Welcome to the secure API',
      'This post is loaded from a parameterized SQLite query.'
    );
    insertPost.run(
      result.lastInsertRowid,
      'Security baseline',
      'JWT authentication, bcrypt hashing, output escaping, and rate limiting are enabled.'
    );
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

export async function createApp(options = {}) {
  const config = options.config || loadConfig();
  const db = options.db || openDatabase(config.databasePath);
  await seedDatabase(db, config.bcryptRounds);

  const selectUserByLogin = db.prepare(
    'SELECT id, login, password_hash, display_name FROM users WHERE login = ?'
  );
  const selectAllPosts = db.prepare(`
    SELECT posts.id, posts.title, posts.body, posts.created_at, users.display_name
    FROM posts
    JOIN users ON users.id = posts.author_id
    ORDER BY posts.id DESC
  `);
  const selectPostById = db.prepare(`
    SELECT posts.id, posts.title, posts.body, posts.created_at, users.display_name
    FROM posts
    JOIN users ON users.id = posts.author_id
    WHERE posts.id = ?
  `);
  const insertPost = db.prepare(
    'INSERT INTO posts (author_id, title, body) VALUES (?, ?, ?)'
  );
  const dummyPasswordHash = await bcrypt.hash(
    'this-password-is-never-valid',
    config.bcryptRounds
  );
  const authenticate = createAuthenticateMiddleware({ db, config });

  const app = express();
  app.disable('x-powered-by');
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'none'"],
          frameAncestors: ["'none'"]
        }
      },
      crossOriginResourcePolicy: { policy: 'same-site' }
    })
  );
  app.use(express.json({ limit: '16kb', strict: true }));

  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { error: 'Too many login attempts. Try again later.' }
  });

  app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
  });

  app.post('/auth/login', loginLimiter, async (req, res, next) => {
    try {
      const validation = validateCredentials(req.body);
      if (!validation.valid) {
        return res.status(400).json({ error: validation.error });
      }

      const { login, password } = validation.value;
      const user = selectUserByLogin.get(login);
      const passwordMatches = await bcrypt.compare(
        password,
        user ? user.password_hash : dummyPasswordHash
      );

      if (!user || !passwordMatches) {
        return res.status(401).json({ error: 'Invalid login or password' });
      }

      return res.json({
        accessToken: signAccessToken(user, config),
        tokenType: 'Bearer',
        expiresIn: config.jwtTtl,
        user: serializeUser(user)
      });
    } catch (error) {
      return next(error);
    }
  });

  app.get('/api/data', authenticate, (req, res) => {
    const posts = selectAllPosts.all().map(serializePost);
    res.json({ data: posts });
  });

  app.post('/api/posts', authenticate, (req, res) => {
    const validation = validatePost(req.body);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    const result = insertPost.run(
      req.user.id,
      validation.value.title,
      validation.value.body
    );
    const createdPost = selectPostById.get(result.lastInsertRowid);
    return res.status(201).json({ post: serializePost(createdPost) });
  });

  app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  app.use((error, req, res, next) => {
    void next;
    if (error.type === 'entity.parse.failed') {
      return res.status(400).json({ error: 'Malformed JSON body' });
    }
    if (error.type === 'entity.too.large') {
      return res.status(413).json({ error: 'Request body is too large' });
    }
    console.error('Unhandled request error:', error.message);
    return res.status(500).json({ error: 'Internal server error' });
  });

  return { app, db };
}

export { DEMO_LOGIN, DEMO_PASSWORD };
