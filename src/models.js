import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, trim: true, unique: true },
  email: { type: String, required: true, lowercase: true, trim: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["user", "admin"], default: "user" },
  createdAt: { type: Date, default: Date.now }
});

const loginSessionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  refreshTokenHash: { type: String, required: true },
  revoked: { type: Boolean, default: false },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});

const securityEventSchema = new mongoose.Schema({
  type: { type: String, enum: ["login_success", "login_failed", "register", "rate_limited"], required: true },
  email: { type: String, default: "unknown", lowercase: true },
  ip: { type: String, default: "unknown" },
  message: { type: String, required: true },
  suspicious: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

export const User = mongoose.model("User", userSchema);
export const SecurityEvent = mongoose.model("SecurityEvent", securityEventSchema);
export const LoginSession = mongoose.model("LoginSession", loginSessionSchema);