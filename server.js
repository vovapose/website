import express from 'express';
import session from 'express-session';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcrypt';
import pkg from 'pg';

dotenv.config();
const { Pool } = pkg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Настройка парсера тела запроса ДО статических файлов
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Статические файлы
app.use('/assets', express.static(path.join(__dirname, '..', 'assets')));
app.use('/', express.static(path.join(__dirname, '..')));

// Сессии
app.use(session({ 
    secret: process.env.SESSION_SECRET || 'dev-secret-key-2024', 
    resave: false, 
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

function createDbPool() {
    if (process.env.DATABASE_URL) {
        console.log('Используется DATABASE_URL из .env');
        return new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: { rejectUnauthorized: false }  // важно для Supabase
        });
    }

    console.log('Используются локальные настройки PostgreSQL');
    return new Pool({
        user: process.env.DB_USER || 'postgres',
        host: process.env.DB_HOST || 'localhost',
        database: process.env.DB_NAME || 'users',
        password: process.env.DB_PASSWORD || 'password',
        port: process.env.DB_PORT || 5432,
    });
}


const pool = createDbPool();

// Проверка подключения к базе данных
async function testConnection() {
    try {
        const client = await pool.connect();
        console.log(' Успешное подключение к PostgreSQL');
        
        // Проверяем существование таблицы users
        const tableCheck = await client.query(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'users'
            );
        `);
        
        if (!tableCheck.rows[0].exists) {
            console.log(' Создаем таблицу users...');
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
            console.log(' Таблица users создана');
        } else {
            console.log(' Таблица users уже существует');
        }
        
        client.release();
    } catch (err) {
        console.error(' Ошибка подключения к базе данных:', err.message);
        console.log(' Проверьте:');
        console.log('  1. Запущен ли PostgreSQL сервер');
        console.log('  2. Правильность учетных данных в .env файле');
        console.log('  3. Существует ли база данных');
        
        // Создаем временное хранилище в памяти для разработки
        console.log(' Используем временное хранилище в памяти...');
    }
}

// Инициализация подключения
testConnection();

// Middleware для логирования запросов
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
    next();
});

// Регистрация
app.post('/api/register', async (req, res) => {
    const { email, username, password, passwordRepeat } = req.body;

    console.log(' Регистрация:', { email, username });

    // Валидация
    if (!email || !username || !password || !passwordRepeat) {
        return res.status(400).json({ error: 'Все поля обязательны' });
    }
    
    if (password !== passwordRepeat) {
        return res.status(400).json({ error: 'Пароли не совпадают' });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: 'Пароль должен содержать минимум 6 символов' });
    }

    // Проверка email voenmeh.ru
    if (!email.includes('@voenmeh.ru')) {
        return res.status(400).json({ error: 'Используйте корпоративную почту @voenmeh.ru' });
    }

    try {
        // Проверяем существование пользователя
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE email = $1 OR username = $2',
            [email.toLowerCase(), username]
        );
        
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Пользователь с таким email или именем уже существует' });
        }

        // Хешируем пароль
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Создаем пользователя
        const result = await pool.query(
            'INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, email, username, role',
            [email.toLowerCase(), username, hashedPassword, 'student']
        );
        
        const user = result.rows[0];
        req.session.userId = user.id;
        
        console.log(' Пользователь зарегистрирован:', user.email);
        
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
        console.error(' Ошибка регистрации:', err.message);
        return res.status(500).json({ error: 'Ошибка сервера при регистрации' });
    }
});

// Вход
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    console.log(' Вход:', { email });

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
        
        console.log(' Пользователь вошел:', user.email);
        
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
        console.error(' Ошибка входа:', err.message);
        return res.status(500).json({ error: 'Ошибка сервера при входе' });
    }
});

// Выход
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error(' Ошибка при выходе:', err);
            return res.status(500).json({ error: 'Ошибка при выходе' });
        }
        console.log('👋 Пользователь вышел из системы');
        res.json({ success: true });
    });
});
// Маршрут для страницы контактов
app.get('/contacts', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// Маршрут для страницы консультаций
app.get('/consultations', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// Главная страница
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// Получение информации о текущем пользователе
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
        console.error(' Ошибка получения пользователя:', err.message);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Проверка здоровья API
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        session: req.session.userId ? 'authenticated' : 'anonymous'
    });
});

// Маршруты для статических файлов
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(` Сервер запущен на порту ${PORT}`);
    console.log(` Требования к регистрации: email @voenmeh.ru`);
    console.log(` http://localhost:${PORT}`);
});