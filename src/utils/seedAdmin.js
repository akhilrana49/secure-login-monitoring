import bcrypt from "bcryptjs";
import { User } from "../models.js";

// Optional admin bootstrap: no separate admin registration is needed.
// Set ADMIN_* values in your local .env before first start.
export async function seedAdmin() {
  const { ADMIN_USERNAME, ADMIN_EMAIL, ADMIN_PASSWORD } = process.env;
  if (!ADMIN_USERNAME || !ADMIN_EMAIL || !ADMIN_PASSWORD) {
    console.log("Admin seed skipped (ADMIN_* values not configured).");
    return;
  }

  const email = ADMIN_EMAIL.toLowerCase().trim();
  const existingAdmin = await User.findOne({ role: "admin" });
  if (existingAdmin) {
    console.log("An admin account already exists; seed skipped.");
    return;
  }

  const existingEmail = await User.findOne({ email });
  if (existingEmail) {
    console.log("Admin email already belongs to a user. Use a different ADMIN_EMAIL.");
    return;
  }

  const password = await bcrypt.hash(ADMIN_PASSWORD, 12);
  await User.create({
    username: ADMIN_USERNAME.trim(),
    email,
    password,
    role: "admin"
  });
  console.log(`Seeded admin account for ${email}. Change the sample password before deployment.`);
}