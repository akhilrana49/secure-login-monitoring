import jwt from "jsonwebtoken";
import { User, LoginSession } from "../models.js";

// Protected routes need both a valid access token and an active server session.
export async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const accessToken = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!accessToken) return res.status(401).json({ message: "Please log in first." });

    // The browser session cookie and the short-lived access token must both be valid.
    if (!req.session?.userId || !req.session?.loginSessionId) {
      return res.status(401).json({ message: "Your login session ended. Please log in again." });
    }

    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
    if (decoded.userId !== String(req.session.userId)) {
      return res.status(401).json({ message: "This token does not match the active session." });
    }

    const [user, loginSession] = await Promise.all([
      User.findById(decoded.userId).select("-password"),
      LoginSession.findOne({
        _id: req.session.loginSessionId,
        userId: decoded.userId,
        revoked: false,
        expiresAt: { $gt: new Date() }
      })
    ]);

    if (!user || !loginSession) {
      return res.status(401).json({ message: "This login session has been revoked. Please log in again." });
    }

    req.user = user;
    req.loginSession = loginSession;
    next();
  } catch {
    return res.status(401).json({ message: "Access token expired or invalid." });
  }
}

// Add this middleware after requireAuth on admin-only routes.
export function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ message: "Admin access required." });
  }
  next();
}