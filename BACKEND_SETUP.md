# Azor Studios Website Backend Setup

This website uses **Node.js + MySQL** for accounts, sessions, admin dashboard, and download tracking.

## 1. Install dependencies

```bash
npm install
```

## 2. Create `.env`

Copy:

```bash
cp .env.example .env
```

Then open `.env` and add your real MySQL password.

Your current MySQL details should look like this:

```env
DB_HOST=mysql.discord.sgp2.shockbyte.host
DB_PORT=3306
DB_NAME=3093d96e32-obs
DB_USER=3093d96e32-obs-admin
DB_PASSWORD=YOUR_REAL_PASSWORD_HERE
SESSION_SECRET=MAKE_THIS_A_LONG_RANDOM_SECRET
ADMIN_USERNAME=Warrior_Playz
ADMIN_PASSWORD=Admin123
ADMIN_EMAIL=admin@obsidian.local
PORT=3000
NODE_ENV=development
```

Important: your username should not include the ending `'` unless Shockbyte actually shows it as part of the username.

## 3. Start website

```bash
npm start
```

Open:

```text
http://localhost:3000
```

## Admin account

The server automatically creates this admin on first start:

```text
Username: Warrior_Playz
Password: Admin123
```

Admin dashboard:

```text
/admin
```

## Security included

- Passwords are hashed with **Argon2id**
- MySQL uses prepared statements
- Sessions use random tokens stored as hashes
- Cookies are `HttpOnly`
- `SameSite=Lax` cookies
- Helmet security headers
- Login/signup rate limiting
- Input validation
- `.env` is ignored by Git

## Very important

Do not upload `.env` to GitHub.
Do not share your MySQL password in Discord or public chats.
Change the default admin password before public launch.


## Fix: Failed to fetch

Login and signup require the Node.js backend. Do not open `index.html` directly and do not use only a static/live server.

Correct way:

```bash
cd Obs
npm install
npm start
```

Then open:

```text
http://localhost:3000
```

If the server fails to start, check that `.env` exists and has the correct MySQL password.

## Password reset emails

Forgot-password emails only send for real if SMTP is configured in `.env`:

```env
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your_email_smtp_username
SMTP_PASSWORD=your_email_smtp_password
MAIL_FROM="Azor Studios <no-reply@yourdomain.com>"
PUBLIC_URL=https://yourdomain.com
```

If SMTP is not configured, the reset link is printed in the server console for development/testing.

## Change password

Logged-in users can use the **Password** button in the navbar to change their password.
