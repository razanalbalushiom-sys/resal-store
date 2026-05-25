Resal Shop - server scaffold

This is a minimal Node.js + Express backend scaffold to make the resal shop professional and secure.

Features:
- SQLite database (better-sqlite3)
- Secure session auth with bcrypt
- Role-based checks for admin and moderator
- File uploads with multer + image resizing using sharp
- Rate limiting + Helmet
- Thawani webhook scaffold

Getting started:
1. cd server
2. copy .env.example to .env and set values
3. npm install
4. npm run dev

The server serves the parent directory (the static frontend) and exposes API endpoints under /api/*.
