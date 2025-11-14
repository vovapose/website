import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.static(path.join(__dirname, '../public')));
app.use(express.json());

// Mock данные для демонстрации
const users = [
    {
        id: 1,
        email: 'demo@voenmeh.ru',
        username: 'demo_user',
        password: 'demo123', // В реальном приложении будет хеш
        role: 'student'
    }
];

// Middleware для проверки аутентификации
const requireAuth = (req, res, next) => {
    // В реальном приложении здесь будет проверка сессии/JWT
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    next();
};

// API routes
app.get('/api/me', (req, res) => {
    // Заглушка - в реальном приложении будет проверка сессии
    const token = req.headers.authorization;
    if (token && token === 'demo-token') {
        return res.json(users[0]);
    }
    res.status(401).json({ error: 'Not authenticated' });
});

app.post('/api/register', (req, res) => {
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
    
    // Проверка существующего пользователя
    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
        return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
    }
    
    // Создание нового пользователя
    const newUser = {
        id: users.length + 1,
        email,
        username,
        password, // В реальном приложении нужно хешировать
        role: 'student',
        createdAt: new Date()
    };
    
    users.push(newUser);
    
    res.status(201).json({
        message: 'Регистрация успешна',
        user: {
            id: newUser.id,
            email: newUser.email,
            username: newUser.username,
            role: newUser.role
        }
    });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email и пароль обязательны' });
    }
    
    const user = users.find(u => u.email === email && u.password === password);
    if (!user) {
        return res.status(401).json({ error: 'Неверный email или пароль' });
    }
    
    res.json({
        message: 'Вход выполнен успешно',
        user: {
            id: user.id,
            email: user.email,
            username: user.username,
            role: user.role
        }
    });
});

app.post('/api/logout', (req, res) => {
    // В реальном приложении здесь будет очистка сессии
    res.json({ message: 'Выход выполнен успешно' });
});

// Serve index.html for all other routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Demo credentials: demo@voenmeh.ru / demo123`);
});