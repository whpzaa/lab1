import jwt from 'jsonwebtoken';
import escapeHtml from 'escape-html';

export function escapeText(value) {
  return escapeHtml(String(value));
}

export function serializeUser(user) {
  return {
    id: user.id,
    login: escapeText(user.login),
    displayName: escapeText(user.display_name)
  };
}

export function serializePost(post) {
  return {
    id: post.id,
    title: escapeText(post.title),
    body: escapeText(post.body),
    author: escapeText(post.display_name),
    createdAt: post.created_at
  };
}

export function signAccessToken(user, config) {
  return jwt.sign(
    { login: user.login },
    config.jwtSecret,
    {
      algorithm: 'HS256',
      audience: config.jwtAudience,
      expiresIn: config.jwtTtl,
      issuer: config.jwtIssuer,
      subject: String(user.id)
    }
  );
}

export function createAuthenticateMiddleware({ db, config }) {
  const findUser = db.prepare(
    'SELECT id, login, display_name FROM users WHERE id = ?'
  );

  return function authenticate(req, res, next) {
    const authorization = req.get('authorization') || '';
    const [scheme, token, extra] = authorization.split(' ');

    if (scheme !== 'Bearer' || !token || extra) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    try {
      const payload = jwt.verify(token, config.jwtSecret, {
        algorithms: ['HS256'],
        audience: config.jwtAudience,
        issuer: config.jwtIssuer
      });

      const userId = Number(payload.sub);
      if (!Number.isInteger(userId) || userId < 1) {
        return res.status(401).json({ error: 'Invalid or expired token' });
      }

      const user = findUser.get(userId);
      if (!user) {
        return res.status(401).json({ error: 'Invalid or expired token' });
      }

      req.user = user;
      return next();
    } catch {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
  };
}

export function validateCredentials(body) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return { valid: false, error: 'Request body must be a JSON object' };
  }

  const { login, password } = body;
  if (typeof login !== 'string' || login.trim().length === 0 || login.length > 64) {
    return { valid: false, error: 'login must be a non-empty string of at most 64 characters' };
  }
  if (typeof password !== 'string' || password.length === 0 || password.length > 256) {
    return { valid: false, error: 'password must be a non-empty string of at most 256 characters' };
  }

  return { valid: true, value: { login: login.trim(), password } };
}

export function validatePost(body) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return { valid: false, error: 'Request body must be a JSON object' };
  }

  const { title, body: postBody } = body;
  if (typeof title !== 'string' || title.trim().length === 0 || title.length > 120) {
    return { valid: false, error: 'title must be a non-empty string of at most 120 characters' };
  }
  if (typeof postBody !== 'string' || postBody.trim().length === 0 || postBody.length > 4000) {
    return { valid: false, error: 'body must be a non-empty string of at most 4000 characters' };
  }

  return { valid: true, value: { title: title.trim(), body: postBody.trim() } };
}
