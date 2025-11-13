voenmeh clean project

This package contains your original frontend (cleaned into index.html + assets) and a minimal Express server
that serves static files and provides simple API endpoints for registration/login using PostgreSQL.

Quick start:

1. Copy `.env.example` to `.env` and fill DATABASE_URL and SESSION_SECRET.
2. Create DB and run `users.sql` to create users table:
   psql -d <your_db> -f users.sql
3. Install dependencies:
   npm install
4. Start server:
   npm start
5. Open http://localhost:3000/index.html

Security notes:
- Registration only allows emails ending with @voenmeh.ru (enforced server-side).
- Passwords are hashed with bcrypt (12 rounds).
