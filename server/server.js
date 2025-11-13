import express from 'express';
import session from 'express-session';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs'; // ИЗМЕНЕНИЕ: bcryptjs вместо bcrypt
import pkg from 'pg';
import express from "express";
import { json } from "body-parser";




dotenv.config();
const { Pool } = pkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(json());

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Статические файлы - правильные пути для вашей структуры
app.use('/assets', express.static(path.join(__dirname, '..', 'assets')));
app.use(express.static(path.join(__dirname, '..')));

// Сессии
app.use(session({ 
    secret: process.env.SESSION_SECRET || 'dev-secret-key-2024', 
    resave: false, 
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
}));

// База данных
function createDbPool() {
    if (process.env.DATABASE_URL) {
        console.log('Using DATABASE_URL from environment');
        return new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: { rejectUnauthorized: false }
        });
    }

    console.log('Using local PostgreSQL settings');
    return new Pool({
        user: process.env.DB_USER || 'postgres',
        host: process.env.DB_HOST || 'localhost',
        database: process.env.DB_NAME || 'users',
        password: process.env.DB_PASSWORD || 'password',
        port: process.env.DB_PORT || 5432,
    });
}

const pool = createDbPool();

// Проверка подключения к БД
async function testConnection() {
    try {
        const client = await pool.connect();
        console.log('✅ PostgreSQL connected successfully');
        
        const tableCheck = await client.query(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'users'
            );
        `);
        
        if (!tableCheck.rows[0].exists) {
            console.log('📊 Creating users table...');
            await client.query(`
                CREATE TABLE users (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(50) DEFAULT 'student',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            `);
            console.log('✅ Users table created');
        } else {
            console.log('✅ Users table exists');
        }
        
        client.release();
    } catch (err) {
        console.error('❌ Database connection error:', err.message);
    }
}

testConnection();

// Middleware для логирования
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
    next();
});

// API Routes
app.post('/api/register', async (req, res) => {
    const { email, username, password, passwordRepeat } = req.body;

    console.log('Register:', { email, username });

    if (!email || !username || !password || !passwordRepeat) {
        return res.status(400).json({ error: 'Все поля обязательны' });
    }
    
    if (password !== passwordRepeat) {
        return res.status(400).json({ error: 'Пароли не совпадают' });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: 'Пароль должен содержать минимум 6 символов' });
    }

    if (!email.includes('@voenmeh.ru')) {
        return res.status(400).json({ error: 'Используйте корпоративную почту @voenmeh.ru' });
    }

    try {
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE email = $1 OR username = $2',
            [email.toLowerCase(), username]
        );
        
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Пользователь с таким email или именем уже существует' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        
        const result = await pool.query(
            'INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, email, username, role',
            [email.toLowerCase(), username, hashedPassword, 'student']
        );
        
        const user = result.rows[0];
        req.session.userId = user.id;
        
        console.log('User registered:', user.email);
        
        return res.json({ 
            success: true, 
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                role: user.role
            }
        });
    } catch (err) {
        console.error('Registration error:', err.message);
        return res.status(500).json({ error: 'Ошибка сервера при регистрации' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    console.log('Login:', { email });

    if (!email || !password) {
        return res.status(400).json({ error: 'Email и пароль обязательны' });
    }

    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email.toLowerCase()]
        );
        
        if (!result.rows.length) {
            return res.status(400).json({ error: 'Пользователь не найден' });
        }
        
        const user = result.rows[0];
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Неверный пароль' });
        }
        
        req.session.userId = user.id;
        
        console.log('User logged in:', user.email);
        
        return res.json({ 
            success: true,
            user: {
                id: user.id,
                email: user.email,
                username: user.username,
                role: user.role
            }
        });
    } catch (err) {
        console.error('Login error:', err.message);
        return res.status(500).json({ error: 'Ошибка сервера при входе' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ error: 'Ошибка при выходе' });
        }
        console.log('User logged out');
        res.json({ success: true });
    });
});

app.get('/api/me', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Не авторизован' });
    }

    try {
        const result = await pool.query(
            'SELECT id, email, username, role FROM users WHERE id = $1',
            [req.session.userId]
        );
        
        if (!result.rows.length) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Get user error:', err.message);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        session: req.session.userId ? 'authenticated' : 'anonymous'
    });
});

// Serve HTML files
app.get('/contacts', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

app.get('/consultations', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

export default app;

// Конфиг для Vercel
export const config = {
  api: {
    bodyParser: false,
  },
};

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📧 Registration requires: @voenmeh.ru email`);
    console.log(`🔗 http://localhost:${PORT}`);
});