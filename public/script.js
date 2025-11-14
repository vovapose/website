import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware для статических файлов
app.use(express.static(path.join(__dirname, '../public')));
app.use(express.json());

// API routes (заглушки)
app.get('/api/me', (req, res) => {
  res.status(200).json({ message: 'Auth not implemented yet' });
});

app.post('/api/register', (req, res) => {
  res.status(200).json({ message: 'Registration not implemented yet' });
});

app.post('/api/login', (req, res) => {
  res.status(200).json({ message: 'Login not implemented yet' });
});

app.post('/api/logout', (req, res) => {
  res.status(200).json({ message: 'Logout not implemented yet' });
});

// Serve index.html for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});