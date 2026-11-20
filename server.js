import express from "express";
import helmet from "helmet";
import pg from "pg";
import rateLimit from "express-rate-limit";
import { readFile } from "node:fs/promises";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import bcrypt from "bcryptjs";

const { Pool } = pg;
const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_SSL === "false" ? false : { rejectUnauthorized: false } });
const PgSession = connectPgSimple(session);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.text({ type: ["text/csv", "text/plain"], limit: "20mb" }));
if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET is required");
}

app.set("trust proxy", 1);

app.use(session({
  store: new PgSession({
    pool,
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 30 * 60 * 1000
  }
}));
app.use(express.static("public"));
app.use("/api/", rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: "draft-7", legacyHeaders: false }));
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many login attempts. Try again later." }
});
function requireSameOrigin(req, res, next) {
  const origin = req.get("origin");
  const expectedOrigin = `${req.protocol}://${req.get("host")}`;

  if (!origin || origin !== expectedOrigin) {
    return res.status(403).json({ error: "Invalid request origin" });
  }

  next();
}
// Admin Login
app.post("/api/admin/login", requireSameOrigin, loginLimiter, async (req, res) => {
  const password = req.body?.password;
  const hash = process.env.ADMIN_PASSWORD_HASH;

  if (!hash || typeof password !== "string") {
    return res.status(401).json({ error: "Invalid login" });
  }

  const valid = await bcrypt.compare(password, hash);

  if (!valid) {
    return res.status(401).json({ error: "Invalid login" });
  }

  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: "Login failed" });

    req.session.isAdmin = true;
    req.session.save((saveErr) => {
      if (saveErr) return res.status(500).json({ error: "Login failed" });
      res.json({ ok: true });
    });
  });
});

// Admin Logout
app.post("/api/admin/logout", requireSameOrigin, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

// Check Admin Session
app.get("/api/admin/me", (req, res) => {
  res.json({ isAdmin: req.session?.isAdmin === true });
});
app.get("/api/health", async (_req, res) => {
  try { const q = await pool.query("SELECT COUNT(*)::int AS count FROM tac_records"); res.json({ ok: true, records: q.rows[0].count }); }
  catch { res.status(503).json({ ok: false, error: "Database unavailable" }); }
});
app.get("/api/tac/:tac", async (req, res) => {
  const tac = req.params.tac;
  if (!/^\d{8}$/.test(tac)) return res.status(400).json({ found: false, error: "TAC must be exactly 8 digits" });
  try {
    const q = await pool.query("SELECT tac, brand, model, device_type, source, verified FROM tac_records WHERE tac=$1 LIMIT 1", [tac]);
    if (!q.rowCount) return res.json({ found: false });
    const r = q.rows[0]; res.json({ found: true, record: { ...r, tac: String(r.tac) } });
  } catch { res.status(503).json({ found: false, error: "Database unavailable" }); }
});
// Admin bulk import: send CSV as text/csv and Authorization: Bearer <TAC_IMPORT_TOKEN>.
// Required header: tac,brand,model. Optional: device_type,source,verified

app.post("/api/admin/import-csv", requireSameOrigin, requireAdmin, async (req, res) => {
  if (typeof req.body !== "string" || !req.body.trim()) {
    return res.status(400).json({
      error: "Send CSV body with Content-Type: text/csv"
    });
  }

  let client;

  try {
    const rows = parseCsv(req.body);

    if (!rows.length) {
      return res.status(400).json({ error: "No valid data rows" });
    }

    const seen = new Set();

    for (const row of rows) {
      if (seen.has(row.tac)) {
        return res.status(400).json({
          error: "Duplicate TAC found in CSV"
        });
      }
      seen.add(row.tac);
    }

    client = await pool.connect();

    await client.query("BEGIN");

    let count = 0;

    for (const r of rows) {
      await client.query(
        `INSERT INTO tac_records
         (tac, brand, model, device_type, source, verified, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW())
         ON CONFLICT (tac) DO UPDATE SET
           brand = EXCLUDED.brand,
           model = EXCLUDED.model,
           device_type = EXCLUDED.device_type,
           source = EXCLUDED.source,
           verified = EXCLUDED.verified,
           updated_at = NOW()`,
        [r.tac, r.brand, r.model, r.device_type, r.source, r.verified]
      );

      count++;
    }

    await client.query("COMMIT");

    res.json({ ok: true, imported: count });

  } catch (error) {
    if (client) {
      try {
        await client.query("ROLLBACK");
      } catch {}
    }

    console.error("CSV import failed:", error.message);

    res.status(500).json({
      error: "CSV import failed. Check CSV format and try again."
    });

  } finally {
    if (client) client.release();
  }
});


function parseCsv(input) {
  const lines = input
    .replace(/^\uFEFF/, "")
    .split(/\r?\n/)
    .filter(line => line.trim());

  if (!lines.length) {
    throw new Error("CSV file is empty");
  }

  function parseLine(line) {
    const result = [];
    let value = "";
    let quoted = false;

    for (let i = 0; i < line.length; i++) {
      const c = line[i];

      if (c === '"') {
        if (quoted && line[i + 1] === '"') {
          value += '"';
          i++;
        } else {
          quoted = !quoted;
        }
      } else if (c === "," && !quoted) {
        result.push(value.trim());
        value = "";
      } else {
        value += c;
      }
    }

    if (quoted) {
      throw new Error("Invalid CSV quote");
    }

    result.push(value.trim());
    return result;
  }

  const headers = parseLine(lines[0])
    .map(value => value.toLowerCase());

  for (const key of ["tac", "brand", "model"]) {
    if (!headers.includes(key)) {
      throw new Error("CSV header must include tac, brand, model");
    }
  }

  if (new Set(headers).size !== headers.length) {
    throw new Error("Duplicate CSV headers");
  }

  const index = key => headers.indexOf(key);

  if (lines.length - 1 > 10000) {
    throw new Error("Maximum 10000 CSV rows allowed");
  }

  return lines.slice(1).map((line, i) => {
    const row = parseLine(line);

    if (row.length !== headers.length) {
      throw new Error(`Invalid columns at CSV row ${i + 2}`);
    }

    const tac = row[index("tac")] || "";
    const brand = row[index("brand")] || "";
    const model = row[index("model")] || "";

    if (!/^\d{8}$/.test(tac)) {
      throw new Error(`Invalid TAC at CSV row ${i + 2}`);
    }

    if (!brand || !model) {
      throw new Error(`Missing brand or model at CSV row ${i + 2}`);
    }

    return {
      tac,
      brand,
      model,
      device_type: row[index("device_type")] || null,
      source: row[index("source")] || "Imported CSV",
      verified: ["true", "1", "yes"].includes(
        (row[index("verified")] || "").toLowerCase()
      )
    };
  });
}



// Check Admin Login Session
function requireAdmin(req, res, next) {
  if (req.session?.isAdmin !== true) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}
// Admin: Search TAC records
app.get("/api/admin/tac", requireAdmin, async (req, res) => {
  const q = String(req.query.q || "").trim().slice(0, 50);

  try {
    const result = await pool.query(
      `SELECT tac, brand, model, device_type, source, verified, updated_at
       FROM tac_records
       WHERE tac LIKE $1 OR brand ILIKE $2 OR model ILIKE $2
       ORDER BY tac
       LIMIT 50`,
      [`%${q}%`, `%${q}%`]
    );

    res.json({ ok: true, records: result.rows });
  } catch {
    res.status(500).json({ error: "Database error" });
  }
});
// Admin: Add a TAC record
app.post("/api/admin/tac", requireSameOrigin, requireAdmin, async (req, res) => {
  const { tac, brand, model, device_type, source } = req.body || {};

  if (!/^\d{8}$/.test(String(tac || "")) ||
      !String(brand || "").trim() ||
      !String(model || "").trim()) {
    return res.status(400).json({ error: "Valid TAC, brand and model required" });
  }

  try {
    await pool.query(
      `INSERT INTO tac_records(tac,brand,model,device_type,source,verified)
       VALUES($1,$2,$3,$4,$5,FALSE)`,
      [tac, brand.trim(), model.trim(), device_type || null,
       source || "Admin entry"]
    );
    res.json({ ok: true, message: "TAC added" });
  } catch (e) {
    if (e.code === "23505")
      return res.status(409).json({ error: "TAC already exists" });
    res.status(500).json({ error: "Database error" });
  }
});

// Admin: Update a TAC record
app.put("/api/admin/tac/:tac", requireSameOrigin, requireAdmin, async (req, res) => {
  const tac = req.params.tac;
  const { brand, model, device_type, source } = req.body || {};

  if (!/^\d{8}$/.test(tac) ||
      !String(brand || "").trim() ||
      !String(model || "").trim()) {
    return res.status(400).json({ error: "Valid TAC, brand and model required" });
  }

  try {
    const q = await pool.query(
      `UPDATE tac_records
       SET brand=$2, model=$3, device_type=$4, source=$5, updated_at=NOW()
       WHERE tac=$1`,
      [tac, brand.trim(), model.trim(), device_type || null,
       source || "Admin edit"]
    );
    res.json({ ok: true, updated: q.rowCount });
  } catch {
    res.status(500).json({ error: "Database error" });
  }
});
// Admin: Delete a TAC record
app.delete("/api/admin/tac/:tac", requireSameOrigin, requireAdmin, async (req, res) => {
  const tac = req.params.tac;

  if (!/^\d{8}$/.test(tac))
    return res.status(400).json({ error: "Invalid TAC" });

  try {
    const q = await pool.query(
      "DELETE FROM tac_records WHERE tac=$1",
      [tac]
    );
    res.json({ ok: true, deleted: q.rowCount });
  } catch {
    res.status(500).json({ error: "Database error" });
  }
});
app.get("/api/account-lock/types", (_req, res) => {
  res.json({
    ok: true,
    brands: [
      { brand: "Apple", lockType: "Activation Lock", status: "not_checked" },
      { brand: "Xiaomi", lockType: "Mi Account Lock", status: "not_checked" },
      { brand: "OPPO", lockType: "OPPO Account Lock", status: "not_checked" },
      { brand: "Vivo", lockType: "Vivo Account Lock", status: "not_checked" },
      { brand: "Huawei", lockType: "Huawei ID Lock", status: "not_checked" },
      { brand: "Realme", lockType: "Realme Account Lock", status: "not_checked" }
    ]
  });
});
app.get("*", (_req,res)=>res.sendFile(process.cwd()+"/public/index.html"));
app.listen(port,()=>console.log(`Myanmar Phone Checker API listening on ${port}`));
