
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || "*"
}));

app.use(express.json({ limit: "1mb" }));

app.use("/api", rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: {
        success: false,
        message: "Too many requests. Please try again later."
    }
}));

// Firebase Admin SDK connection
try {
    const serviceAccount = JSON.parse(
        process.env.FIREBASE_SERVICE_ACCOUNT
    );

    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });

    console.log("Firebase connected successfully!");

} catch (error) {
    console.error("Firebase connection failed:", error.message);
    process.exit(1);
}

const db = admin.firestore();

// Home route
app.get("/", (req, res) => {
    res.send("Fixora Hub Backend is running!");
});

// Health check
app.get("/api/health", (req, res) => {
    res.json({
        success: true,
        message: "Fixora Hub API is running"
    });
});

// Firebase connection test
app.get("/api/firebase-test", async (req, res) => {
    try {
        await db.collection("serverChecks").doc("connection").set({
            status: "connected",
            checkedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({
            success: true,
            message: "Firebase Firestore connected successfully!"
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            success: false,
            message: "Firebase connection test failed"
        });
    }
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
});
