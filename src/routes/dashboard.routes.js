import express from "express";
import { User, SecurityEvent } from "../models.js";
import { requireAuth, requireAdmin } from "../middleware/auth.js";

const router = express.Router();

router.get("/summary", requireAuth, requireAdmin, async (req, res) => {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const [users, events, failedLogins, rateLimited, suspiciousEvents, recentEvents] = await Promise.all([
      User.countDocuments({ role: "user" }),
      SecurityEvent.countDocuments(),
      SecurityEvent.countDocuments({ type: "login_failed", createdAt: { $gte: since } }),
      SecurityEvent.countDocuments({ type: "rate_limited", createdAt: { $gte: since } }),
      SecurityEvent.countDocuments({ suspicious: true, createdAt: { $gte: since } }),
      SecurityEvent.find().sort({ createdAt: -1 }).limit(100).lean()
    ]);

    res.json({
      stats: { users, events, failedLogins, rateLimited, suspiciousEvents },
      events: recentEvents.map(event => ({
        id: event._id,
        type: event.type,
        email: event.email,
        ip: event.ip,
        message: event.message,
        suspicious: event.suspicious,
        createdAt: event.createdAt
      }))
    });
  } catch {
    res.status(500).json({ message: "Could not load dashboard data." });
  }
});

router.get("/users", requireAuth, requireAdmin, async (req, res) => {
  const users = await User.find().select("username email role createdAt").sort({ createdAt: -1 }).limit(100);
  res.json({ users });
});

export default router;