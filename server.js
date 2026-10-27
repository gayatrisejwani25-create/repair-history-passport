const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const app = express();

app.use(express.json({ limit: "2mb" }));

const allowedOrigin = process.env.FRONTEND_URL;

app.use(cors({
  origin: allowedOrigin || "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET environment variable is missing");
}

if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  throw new Error("FIREBASE_SERVICE_ACCOUNT environment variable is missing");
}

// Firebase connection
const serviceAccount = JSON.parse(
  process.env.FIREBASE_SERVICE_ACCOUNT
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const users = db.collection("users");
const products = db.collection("products");
const repairs = db.collection("repairs");

// Authentication middleware
function authenticate(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Login required"
    });
  }

  const token = header.split(" ")[1];

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired session"
    });
  }
}

// Role middleware
function allowRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: "You do not have permission"
      });
    }

    next();
  };
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Fixora Hub backend is running"
  });
});

// REGISTER
app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
      return res.status(400).json({
        success: false,
        message: "All fields are required"
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 8 characters"
      });
    }

    if (!["customer", "repair_shop_owner"].includes(role)) {
      return res.status(400).json({
        success: false,
        message: "Invalid account type"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existing = await users
      .where("email", "==", normalizedEmail)
      .limit(1)
      .get();

    if (!existing.empty) {
      return res.status(409).json({
        success: false,
        message: "Email is already registered"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const userRef = users.doc();

    await userRef.set({
      name: name.trim(),
      email: normalizedEmail,
      password: passwordHash,
      role,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.status(201).json({
      success: true,
      message: "Account created successfully"
    });

  } catch (error) {
    console.error("Register error:", error);

    res.status(500).json({
      success: false,
      message: "Registration failed"
    });
  }
});

// LOGIN
app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const snapshot = await users
      .where("email", "==", normalizedEmail)
      .limit(1)
      .get();

    if (snapshot.empty) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password"
      });
    }

    const userDoc = snapshot.docs[0];
    const userData = userDoc.data();

    const validPassword = await bcrypt.compare(
      password,
      userData.password
    );

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password"
      });
    }

    const token = jwt.sign(
      {
        id: userDoc.id,
        email: userData.email,
        role: userData.role
      },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      success: true,
      token,
      user: {
        id: userDoc.id,
        name: userData.name,
        email: userData.email,
        role: userData.role
      }
    });

  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      success: false,
      message: "Login failed"
    });
  }
});

// GET CURRENT USER
app.get("/api/me", authenticate, async (req, res) => {
  try {
    const doc = await users.doc(req.user.id).get();

    if (!doc.exists) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    const data = doc.data();

    res.json({
      success: true,
      user: {
        id: doc.id,
        name: data.name,
        email: data.email,
        role: data.role
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Could not load user"
    });
  }
});

// GET PRODUCTS
app.get("/api/products", authenticate, async (req, res) => {
  try {
    let query = products;

    if (req.user.role !== "admin") {
      query = query.where("ownerId", "==", req.user.id);
    }

    const snapshot = await query.get();

    const result = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json({
      success: true,
      products: result
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Could not load products"
    });
  }
});

// ADD PRODUCT
app.post(
  "/api/products",
  authenticate,
  allowRoles("customer", "repair_shop_owner", "admin"),
  async (req, res) => {
    try {
      const {
        name,
        brand,
        model,
        serial,
        purchaseDate,
        warrantyMonths,
        notes
      } = req.body;

      if (!name || !brand || !purchaseDate) {
        return res.status(400).json({
          success: false,
          message: "Product name, brand and purchase date are required"
        });
      }

      const productRef = products.doc();

      const product = {
        ownerId: req.user.id,
        owner: req.user.email,
        name: String(name).trim(),
        brand: String(brand).trim(),
        model: model || "",
        serial: serial || "",
        purchaseDate,
        warrantyMonths: Number(warrantyMonths || 0),
        notes: notes || "",
        transfers: [],
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      };

      await productRef.set(product);

      res.status(201).json({
        success: true,
        message: "Product registered successfully",
        product: {
          id: productRef.id,
          ...product
        }
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Could not register product"
      });
    }
  }
);

// UPDATE PRODUCT
app.put("/api/products/:id", authenticate, async (req, res) => {
  try {
    const ref = products.doc(req.params.id);
    const doc = await ref.get();

    if (!doc.exists) {
      return res.status(404).json({
        success: false,
        message: "Product not found"
      });
    }

    const data = doc.data();

    if (data.ownerId !== req.user.id && req.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Not allowed"
      });
    }

    const allowed = [
      "name",
      "brand",
      "model",
      "serial",
      "purchaseDate",
      "warrantyMonths",
      "notes"
    ];

    const updates = {};

    allowed.forEach(key => {
      if (req.body[key] !== undefined) {
        updates[key] = req.body[key];
      }
    });

    await ref.update(updates);

    res.json({
      success: true,
      message: "Product updated successfully"
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Could not update product"
    });
  }
});

// DELETE PRODUCT
app.delete("/api/products/:id", authenticate, async (req, res) => {
  try {
    const ref = products.doc(req.params.id);
    const doc = await ref.get();

    if (!doc.exists) {
      return res.status(404).json({
        success: false,
        message: "Product not found"
      });
    }

    if (
      doc.data().ownerId !== req.user.id &&
      req.user.role !== "admin"
    ) {
      return res.status(403).json({
        success: false,
        message: "Not allowed"
      });
    }

    const repairDocs = await repairs
      .where("productId", "==", req.params.id)
      .get();

    const batch = db.batch();

    repairDocs.forEach(repair => {
      batch.delete(repair.ref);
    });

    batch.delete(ref);

    await batch.commit();

    res.json({
      success: true,
      message: "Product and repair records deleted"
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Could not delete product"
    });
  }
});

// GET REPAIR HISTORY
app.get("/api/repairs", authenticate, async (req, res) => {
  try {
    const snapshot = await repairs
      .where("ownerId", "==", req.user.id)
      .get();

    res.json({
      success: true,
      repairs: snapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }))
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Could not load repair history"
    });
  }
});

// ADD REPAIR
app.post(
  "/api/repairs",
  authenticate,
  allowRoles("repair_shop_owner", "admin"),
  async (req, res) => {
    try {
      const {
        productId,
        date,
        description,
        shop,
        cost
      } = req.body;

      if (!productId || !date || !description) {
        return res.status(400).json({
          success: false,
          message: "Product, date and description are required"
        });
      }

      const productDoc = await products.doc(productId).get();

      if (!productDoc.exists) {
        return res.status(404).json({
          success: false,
          message: "Product not found"
        });
      }

      const product = productDoc.data();

      const repairRef = repairs.doc();

      await repairRef.set({
        productId,
        ownerId: product.ownerId,
        technicianId: req.user.id,
        date,
        description: String(description).trim(),
        shop: shop || "",
        cost: Number(cost || 0),
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });

      res.status(201).json({
        success: true,
        message: "Repair record saved",
        repairId: repairRef.id
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Could not save repair"
      });
    }
  }
);

// OWNERSHIP TRANSFER
app.post(
  "/api/products/:id/transfer",
  authenticate,
  async (req, res) => {
    try {
      const { newOwnerEmail } = req.body;

      if (!newOwnerEmail) {
        return res.status(400).json({
          success: false,
          message: "New owner's email is required"
        });
      }

      const productRef = products.doc(req.params.id);
      const productDoc = await productRef.get();

      if (!productDoc.exists) {
        return res.status(404).json({
          success: false,
          message: "Product not found"
        });
      }

      const product = productDoc.data();

      if (
        product.ownerId !== req.user.id &&
        req.user.role !== "admin"
      ) {
        return res.status(403).json({
          success: false,
          message: "Only the current owner can transfer this product"
        });
      }

      const email = newOwnerEmail.trim().toLowerCase();

      const newOwnerSnapshot = await users
        .where("email", "==", email)
        .limit(1)
        .get();

      if (newOwnerSnapshot.empty) {
        return res.status(404).json({
          success: false,
          message: "New owner must create an account first"
        });
      }

      const newOwnerDoc = newOwnerSnapshot.docs[0];

      const transfer = {
        from: product.owner,
        to: email,
        date: new Date().toISOString()
      };

      await productRef.update({
        ownerId: newOwnerDoc.id,
        owner: email,
        transfers: admin.firestore.FieldValue.arrayUnion(transfer)
      });

      res.json({
        success: true,
        message: "Ownership transferred successfully"
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Transfer failed"
      });
    }
  }
);

// PUBLIC PASSPORT VERIFICATION
app.get("/api/passport/:id", async (req, res) => {
  try {
    const doc = await products.doc(req.params.id).get();

    if (!doc.exists) {
      return res.status(404).json({
        success: false,
        message: "Passport not found"
      });
    }

    const product = doc.data();

    res.json({
      success: true,
      passport: {
        id: doc.id,
        name: product.name,
        brand: product.brand,
        model: product.model,
        purchaseDate: product.purchaseDate,
        warrantyMonths: product.warrantyMonths,
        transfers: product.transfers || []
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Verification failed"
    });
  }
});

// START SERVER
app.listen(PORT, () => {
  console.log(`Fixora Hub running on port ${PORT}`);
});
