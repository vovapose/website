import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

// ⚠️ ЕСЛИ ЭТИХ ПАКЕТОВ НЕТ - СКАЖИ, ДАМ АЛЬТЕРНАТИВУ
import pkg from 'pg';
import bcrypt from 'bcryptjs';
import session from 'express-session';

const { Client } = pkg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.static(path.join(__dirname, '../public')));
app.use(express.json());

// ⚠️ ЕСЛИ session НЕТ - УБРАТЬ ЭТУ СТРОКУ И ВСЮДЕ session
app.use(session({
  secret: 'voenmeh-kafedra-o7-2024-session-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// Функция для работы с базой
async function dbQuery(sql, params = []) {
  console.log('🔄 Executing query:', sql);
  
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });

  try {
    await client.connect();
    const result = await client.query(sql, params);
    console.log('✅ Query successful');
    return result;
  } catch (error) {
    console.error('❌ Database error:', error.message);
    throw error;
  } finally {
    await client.end();
  }
}

// Health check - покажет статус базы
app.get('/api/health', async (req, res) => {
  try {
    const result = await dbQuery('SELECT NOW() as time');
    res.json({
      status: 'OK',
      database: 'CONNECTED ✅',
      time: result.rows[0].time,
      message: 'База данных подключена!'
    });
  } catch (error) {
    res.json({
      status: 'OK',
      database: 'DISCONNECTED ❌',
      error: error.message,
      message: 'Сервер работает, но база не подключена'
    });
  }
});

// API endpoints с реальной базой
app.get('/api/me', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    const result = await dbQuery(
      'SELECT id, email, username, role, created_at FROM users WHERE id = $1',
      [req.session.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
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
    const existingUser = await dbQuery(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
    }

    // Хешируем пароль
    const passwordHash = await bcrypt.hash(password, 12);

    // Создаем пользователя
    const result = await dbQuery(
      `INSERT INTO users (email, username, password_hash, role) 
       VALUES ($1, $2, $3, 'student') 
       RETURNING id, email, username, role, created_at`,
      [email, username, passwordHash]
    );

    const newUser = result.rows[0];
    req.session.userId = newUser.id;

    res.json({
      message: 'Регистрация успешна!',
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
    const result = await dbQuery(
      'SELECT id, email, username, password_hash, role FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }

    req.session.userId = user.id;
    const { password_hash, ...userWithoutPassword } = user;

    res.json({
      message: 'Вход выполнен успешно!',
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
    res.json({ message: 'Выход выполнен успешно' });
  });
});

// Serve index.html for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Для Vercel - экспорт app
export default app;