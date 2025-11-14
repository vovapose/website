import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import pkg from 'pg';
import bcrypt from 'bcryptjs';
import session from 'express-session';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pkg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Подключение к Supabase
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(express.static(path.join(__dirname, '../public')));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 } // 24 часа
}));

// Проверка подключения к базе
pool.connect((err, client, release) => {
  if (err) {
    console.error('Ошибка подключения к базе данных:', err);
  } else {
    console.log('✅ Успешное подключение к Supabase PostgreSQL');
    release();
  }
});

// Middleware для проверки аутентификации
const requireAuth = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.status(401).json({ error: 'Требуется аутентификация' });
  }
};

// API routes
app.get('/api/me', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    const result = await pool.query(
      'SELECT id, email, username, role, created_at FROM users WHERE id = $1',
      [req.session.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/register', async (req, res) => {
  const { email, username, password, passwordRepeat } = req.body;

  // Валидация
  if (!email || !username || !password) {
    return res.status(400).json({ error: 'Все поля обязательны' });
  }

  if (password !== passwordRepeat) {
    return res.status(400).json({ error: 'Пароли не совпадают' });
  }

  if (!email.endsWith('@voenmeh.ru')) {
    return res.status(400).json({ error: 'Разрешены только email @voenmeh.ru' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Пароль должен быть не менее 6 символов' });
  }

  try {
    // Проверяем существующего пользователя
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
    }

    // Хешируем пароль
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Создаем пользователя
    const result = await pool.query(
      `INSERT INTO users (email, username, password_hash, role) 
       VALUES ($1, $2, $3, 'student') 
       RETURNING id, email, username, role, created_at`,
      [email, username, passwordHash]
    );

    const newUser = result.rows[0];

    // Создаем сессию
    req.session.userId = newUser.id;

    res.status(201).json({
      message: 'Регистрация успешна',
      user: newUser
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Ошибка при регистрации' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email и пароль обязательны' });
  }

  try {
    // Ищем пользователя
    const result = await pool.query(
      'SELECT id, email, username, password_hash, role FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }

    const user = result.rows[0];

    // Проверяем пароль
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }

    // Создаем сессию
    req.session.userId = user.id;

    // Возвращаем пользователя без пароля
    const { password_hash, ...userWithoutPassword } = user;

    res.json({
      message: 'Вход выполнен успешно',
      user: userWithoutPassword
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Ошибка при входе' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Ошибка при выходе' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Выход выполнен успешно' });
  });
});

// Serve index.html for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Database: ${process.env.DATABASE_URL ? 'Connected to Supabase' : 'Not configured'}`);
});