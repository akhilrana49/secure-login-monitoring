// import express from "express";
// import mongoose from "mongoose";
// import session from "express-session";
// import cookieParser from "cookie-parser";
// import MongoStore from "connect-mongo";
// import dotenv from "dotenv";
// import path from "path";
// import { fileURLToPath } from "url";
// import authRoutes from "./src/routes/auth.routes.js";
// import dashboardRoutes from "./src/routes/dashboard.routes.js";
// import { seedAdmin } from "./src/utils/seedAdmin.js";

// dotenv.config();

// const app = express();
// const PORT = process.env.PORT || 5000;
// const __filename = fileURLToPath(import.meta.url);
// const __dirname = path.dirname(__filename);

// app.use(express.json());
// app.use(cookieParser());
// app.use(express.static(path.join(__dirname, "public")));

// // Connect to MongoDB, configure sessions, and then start the server.
// async function startServer() {
//   try {
//     if (!process.env.MONGODB_URI) {
//       throw new Error("MONGODB_URI is missing. Copy .env.example to .env and configure it.");
//     }
//     if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 24) {
//       throw new Error("JWT_SECRET must be set to a secret with at least 24 characters.");
//     }

//     if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 24) {
//       throw new Error("SESSION_SECRET must be set to a secret with at least 24 characters.");
//     }

//     await mongoose.connect(process.env.MONGODB_URI);
//     console.log("Connected to MongoDB");

//     // Store Express session data in MongoDB so it survives server restarts.
//     app.use(session({
//       name: "sentinel.sid",
//       secret: process.env.SESSION_SECRET,
//       resave: false,
//       saveUninitialized: false,
//       store: MongoStore.create({
//         mongoUrl: process.env.MONGODB_URI,
//         collectionName: "express_sessions",
//         ttl: 7 * 24 * 60 * 60
//       }),
//       cookie: {
//         httpOnly: true,
//         sameSite: "lax",
//         secure: process.env.NODE_ENV === "production",
//         maxAge: 7 * 24 * 60 * 60 * 1000
//       }
//     }));

//     app.use("/api/auth", authRoutes);
//     app.use("/api/dashboard", dashboardRoutes);

//     app.get("/api/health", (req, res) => {
//       res.json({ success: true, message: "Secure Login Monitoring API is running" });
//     });
//     app.get("*", (req, res) => {
//       res.sendFile(path.join(__dirname, "public", "index.html"));
//     });

//     await seedAdmin();

//     app.listen(PORT, () => {
//       console.log(`Secure Login Monitoring running at http://localhost:${PORT}`);
//     });
//   } catch (error) {
//     console.error("Startup failed:", error.message);
//     process.exit(1);
//   }
// }

// startServer();

import express from "express";
import mongoose from "mongoose";
import session from "express-session";
import cookieParser from "cookie-parser";
import MongoStore from "connect-mongo";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

import authRoutes from "./src/routes/auth.routes.js";
import dashboardRoutes from "./src/routes/dashboard.routes.js";
import { seedAdmin } from "./src/utils/seedAdmin.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.set("trust proxy", 1);

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// Sessions are stored in MongoDB.
app.use(
  session({
    name: "sentinel.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      collectionName: "express_sessions",
      ttl: 7 * 24 * 60 * 60,
    }),
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    },
  })
);

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/dashboard", dashboardRoutes);

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Secure Login Monitoring API is running",
  });
});

// Open the frontend.
app.use((req, res, next) => {
  if (req.method !== "GET" || req.path.startsWith("/api/")) {
    return next();
  }

  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Connect to MongoDB, create the admin if needed, then start.
async function startServer() {
  try {
    if (!process.env.MONGODB_URI) {
      throw new Error("MONGODB_URI is missing");
    }

    if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 24) {
      throw new Error("JWT_SECRET must have at least 24 characters");
    }

    if (
      !process.env.SESSION_SECRET ||
      process.env.SESSION_SECRET.length < 24
    ) {
      throw new Error("SESSION_SECRET must have at least 24 characters");
    }

    await mongoose.connect(process.env.MONGODB_URI);
    console.log("Connected to MongoDB");

    await seedAdmin();

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Startup failed:", error.message);
    process.exit(1);
  }
}

startServer();



