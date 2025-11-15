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

// Test endpoint - ДОЛЖЕН РАБОТАТЬ
app.get('/api/test', (req, res) => {
  res.json({ 
    message: '✅ API работает!',
    timestamp: new Date().toISOString()
  });
});

// Health endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK',
    server: 'working',
    database: process.env.DATABASE_URL ? 'configured' : 'not configured'
  });
});

// Serve index.html for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});