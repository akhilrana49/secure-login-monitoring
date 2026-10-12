import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import rateLimit from "express-rate-limit";
import { User, SecurityEvent, LoginSession } from "../models.js";
import { logEvent, getClientIp } from "../utils/logEvent.js";
import { requireAuth } from "../middleware/auth.js";

// Authentication endpoints are grouped in this file.
const router = express.Router();
const REFRESH_COOKIE = "sentinel.refresh";

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: true,
  legacyHeaders: false,
  handler: async (req, res) => {
    await logEvent({
      type: "rate_limited",
      email: String(req.body?.email || "unknown").toLowerCase(),
      ip: getClientIp(req),
      message: "Too many login attempts from this address.",
      suspicious: true
    });
    res.status(429).json({ message: "Too many attempts. Please wait 15 minutes and try again." });
  }
});

// Access tokens are short-lived and sent in the Authorization header.
function createAccessToken(user) {
  return jwt.sign(
    { userId: user._id.toString(), role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || "15m" }
  );
}

// Store only a hash of the refresh token in MongoDB.
function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function refreshDays() {
  return Math.max(1, Number(process.env.REFRESH_TOKEN_DAYS || 7));
}

function setRefreshCookie(res, token) {
  res.cookie(REFRESH_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/api/auth",
    maxAge: refreshDays() * 24 * 60 * 60 * 1000
  });
}

function clearRefreshCookie(res) {
  res.clearCookie(REFRESH_COOKIE, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/api/auth"
  });
}

// Create one server-side login session for this browser/device.
async function startLoginSession(req, res, user) {
  const refreshToken = crypto.randomBytes(48).toString("hex");
  const expiresAt = new Date(Date.now() + refreshDays() * 24 * 60 * 60 * 1000);

  const loginSession = await LoginSession.create({
    userId: user._id,
    refreshTokenHash: hashToken(refreshToken),
    expiresAt
  });

  req.session.userId = user._id.toString();
  req.session.loginSessionId = loginSession._id.toString();

  await new Promise((resolve, reject) => {
    req.session.save(error => error ? reject(error) : resolve());
  });

  setRefreshCookie(res, refreshToken);
  return { accessToken: createAccessToken(user) };
}

// Register the user, hash the password, log the event, and sign them in.
router.post("/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (username.length < 3) return res.status(400).json({ message: "Username must be at least 3 characters." });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ message: "Enter a valid email address." });
    if (password.length < 8) return res.status(400).json({ message: "Password must be at least 8 characters." });

    const alreadyExists = await User.findOne({ $or: [{ email }, { username }] });
    if (alreadyExists) return res.status(409).json({ message: "Username or email is already registered." });

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await User.create({ username, email, password: hashedPassword });
    await logEvent({ type: "register", email, ip: getClientIp(req), message: `New account registered: ${username}` });

    const auth = await startLoginSession(req, res, user);
    res.status(201).json({
      message: "Account created successfully.",
      accessToken: auth.accessToken,
      user: { id: user._id, username: user.username, email: user.email, role: user.role }
    });
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ message: "Username or email is already registered." });
    res.status(500).json({ message: "Could not create account." });
  }
});

// Check credentials and record successful or failed login attempts.
router.post("/login", loginLimiter, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const ip = getClientIp(req);

  try {
    const user = await User.findOne({ email });
    const passwordMatches = user ? await bcrypt.compare(password, user.password) : false;

    if (!passwordMatches) {
      await logEvent({ type: "login_failed", email: email || "unknown", ip, message: "Failed login attempt.", suspicious: true });
      return res.status(401).json({ message: "Invalid email or password." });
    }

    await logEvent({ type: "login_success", email, ip, message: `Successful login for ${user.username}` });
    const auth = await startLoginSession(req, res, user);
    res.json({
      message: "Login successful.",
      accessToken: auth.accessToken,
      user: { id: user._id, username: user.username, email: user.email, role: user.role }
    });
  } catch {
    res.status(500).json({ message: "Could not log in. Check your database connection." });
  }
});

// Access tokens are short-lived. This endpoint rotates the refresh token and returns a new access token.
// Validate and rotate the refresh token, then issue a new access token.
router.post("/refresh", async (req, res) => {
  try {
    const refreshToken = req.cookies?.[REFRESH_COOKIE];
    const sessionId = req.session?.loginSessionId;
    const userId = req.session?.userId;
    if (!refreshToken || !sessionId || !userId) {
      return res.status(401).json({ message: "Please log in again." });
    }

    const loginSession = await LoginSession.findOne({
      _id: sessionId,
      userId,
      revoked: false,
      expiresAt: { $gt: new Date() }
    });
    if (!loginSession || loginSession.refreshTokenHash !== hashToken(refreshToken)) {
      if (loginSession) {
        loginSession.revoked = true;
        await loginSession.save();
      }
      return res.status(401).json({ message: "Refresh token is invalid. Please log in again." });
    }

    const user = await User.findById(userId);
    if (!user) return res.status(401).json({ message: "Account no longer exists." });

    const nextRefreshToken = crypto.randomBytes(48).toString("hex");
    loginSession.refreshTokenHash = hashToken(nextRefreshToken);
    loginSession.expiresAt = new Date(Date.now() + refreshDays() * 24 * 60 * 60 * 1000);
    await loginSession.save();
    setRefreshCookie(res, nextRefreshToken);

    res.json({ accessToken: createAccessToken(user) });
  } catch {
    res.status(500).json({ message: "Could not refresh your session." });
  }
});

// Users can see security events associated with their own email.
router.get("/security-summary", requireAuth, async (req, res) => {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const email = req.user.email.toLowerCase();
    const [failedLogins, rateLimited, recentEvents] = await Promise.all([
      SecurityEvent.countDocuments({ email, type: "login_failed", createdAt: { $gte: since } }),
      SecurityEvent.countDocuments({ email, type: "rate_limited", createdAt: { $gte: since } }),
      SecurityEvent.find({ email }).sort({ createdAt: -1 }).limit(25).lean()
    ]);

    res.json({
      summary: { failedLogins, rateLimited, suspicious: failedLogins + rateLimited },
      events: recentEvents.map(event => ({
        id: event._id, type: event.type, message: event.message,
        suspicious: event.suspicious, createdAt: event.createdAt
      }))
    });
  } catch {
    res.status(500).json({ message: "Could not load your security activity." });
  }
});

// Logout uses the server-side session: revoke the login record and destroy the Express session.
router.post("/logout", requireAuth, async (req, res) => {
  try {
    req.loginSession.revoked = true;
    await req.loginSession.save();
    clearRefreshCookie(res);
    req.session.destroy(error => {
      if (error) return res.status(500).json({ message: "Could not end session." });
      res.clearCookie("sentinel.sid", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" });
      res.json({ message: "Logged out successfully." });
    });
  } catch {
    res.status(500).json({ message: "Could not log out." });
  }
});

// Revoke all login-session records and clear this browser's session. Other devices fail their next API check.
router.post("/logout-all", requireAuth, async (req, res) => {
  try {
    await LoginSession.updateMany({ userId: req.user._id, revoked: false }, { $set: { revoked: true } });
    clearRefreshCookie(res);
    req.session.destroy(error => {
      if (error) return res.status(500).json({ message: "Could not end session." });
      res.clearCookie("sentinel.sid", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" });
      res.json({ message: "All devices have been signed out. Please log in again." });
    });
  } catch {
    res.status(500).json({ message: "Could not sign out all devices." });
  }
});

// Return the signed-in user’s basic profile.
router.get("/me", requireAuth, (req, res) => {
  res.json({
    user: { id: req.user._id, username: req.user.username, email: req.user.email, role: req.user.role }
  });
});

export default router;