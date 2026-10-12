# Secure Login Monitoring & Threat Detection System

A beginner-friendly Node.js + Express + MongoDB project. It records login activity, detects repeated failed logins, and gives admins a dashboard to review events.

## Run the project

1. Install Node.js and make sure MongoDB is running (local MongoDB or Atlas).
2. Copy `.env.example` to `.env`.
3. Set `MONGODB_URI`, `JWT_SECRET`, and `SESSION_SECRET`. Keep the admin settings for a local demo, and change the sample password. Secrets should be long and private.
4. In this folder, run `npm install`.
5. Run `npm run dev`.
6. Open `http://localhost:5000`.

The admin account is created automatically on startup if `ADMIN_USERNAME`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` are configured and no admin account exists yet.

## Features to explain in an interview

- **Registration and login:** Express routes receive form data. `bcryptjs` hashes passwords and checks passwords during login.
- **Access token:** A signed JWT that expires after 15 minutes by default. The frontend keeps it in memory and sends it as `Authorization: Bearer ...`.
- **Refresh token:** A random token sent in an `HttpOnly` cookie. MongoDB stores its SHA-256 hash. The refresh endpoint checks it, rotates it, and returns a new access token.
- **Server-side session:** `express-session` uses a session cookie; `connect-mongo` stores session data in MongoDB. Protected API requests require both the access token and an active session.
- **Logout:** The server revokes the current login record and destroys the current Express session.
- **Logout all devices:** All login-session records for the user are revoked. Other devices are rejected on their next protected API request.
- **Rate limiting:** The login endpoint allows up to 8 attempts in a 15-minute window from the same client key; blocked attempts are logged.
- **Security event logging:** Successful logins, failed logins, registrations, and rate-limit blocks are stored in MongoDB.
- **Role-based access:** `requireAuth` checks authentication; `requireAdmin` restricts admin dashboard endpoints.
- **Dashboards:** Users see activity linked to their email. Admins can review recent events and registered accounts.

## Where to find the important code

| File | Purpose |
|---|---|
| `server.js` | Starts Express, connects MongoDB, configures sessions, and mounts routes |
| `src/models.js` | MongoDB schemas for users, login sessions, and security events |
| `src/routes/auth.routes.js` | Register, login, refresh token, logout, logout all devices, and personal activity |
| `src/middleware/auth.js` | Validates access JWT + server session; checks admin role |
| `src/routes/dashboard.routes.js` | Admin statistics, recent events, and user list |
| `src/utils/logEvent.js` | Saves security events and gets the client IP |
| `src/utils/seedAdmin.js` | Creates the initial admin account from `.env` |
| `public/app.js` | Form actions, API requests, automatic token refresh, and dashboard updates |
| `public/index.html` | Dashboard and login/register page structure |
| `public/styles.css` | UI styling |

## Simple authentication flow

1. User submits email and password.
2. Server finds the user and checks the password with bcrypt.
3. Server creates a login-session record, an Express session, an access JWT, and a refresh cookie.
4. Frontend sends the access JWT with protected API requests.
5. When the access JWT expires, the frontend calls `/api/auth/refresh`; the server validates and rotates the refresh token.
6. Logout revokes the login-session record and destroys the Express session.

## Important notes

- The refresh token is stored in an `HttpOnly` cookie so frontend JavaScript cannot read it.
- For local development, cookies are not marked `Secure` unless `NODE_ENV=production`; production should use HTTPS.
- User-side event history is matched by the email entered at login. If someone targets an account using a different email, that event may not appear on the account owner's page.
- This is a learning project. Before public deployment, add production-grade CSRF protection, trusted-proxy configuration, monitoring, and broader security testing.
