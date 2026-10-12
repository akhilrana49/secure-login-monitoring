import { SecurityEvent } from "../models.js";

// Store security events in MongoDB so the dashboard can show a history.
export async function logEvent({ type, email, ip, message, suspicious = false }) {
  try {
    await SecurityEvent.create({ type, email, ip, message, suspicious });
  } catch (error) {
    console.error("Could not save security event:", error.message);
  }
}

export function getClientIp(req) {
  // Avoid trusting arbitrary forwarded headers unless your deployment configures a trusted proxy.
  return req.ip || req.socket.remoteAddress || "unknown";
}