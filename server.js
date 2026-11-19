import express from "express";
import helmet from "helmet";
import pg from "pg";
import rateLimit from "express-rate-limit";
import { readFile } from "node:fs/promises";

const { Pool } = pg;
const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_SSL === "false" ? false : { rejectUnauthorized: false } });
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.text({ type: ["text/csv", "text/plain"], limit: "20mb" }));
app.use(express.static("public"));
app.use("/api/", rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: "draft-7", legacyHeaders: false }));

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
app.post("/api/admin/import-csv", async (req, res) => {
  const token = process.env.TAC_IMPORT_TOKEN;
  if (!token || req.get("authorization") !== `Bearer ${token}`) return res.status(401).json({ error: "Unauthorized" });
  if (typeof req.body !== "string" || !req.body.trim()) return res.status(400).json({ error: "Send CSV body with Content-Type: text/csv" });
  try {
    const rows = parseCsv(req.body);
    if (!rows.length) return res.status(400).json({ error: "No valid data rows" });
    const client = await pool.connect(); let count = 0;
    try {
      await client.query("BEGIN");
      for (const r of rows) {
        await client.query(`INSERT INTO tac_records(tac,brand,model,device_type,source,verified,updated_at)
          VALUES($1,$2,$3,$4,$5,$6,NOW())
          ON CONFLICT(tac) DO UPDATE SET brand=EXCLUDED.brand, model=EXCLUDED.model,
          device_type=EXCLUDED.device_type, source=EXCLUDED.source, verified=EXCLUDED.verified, updated_at=NOW()`,
          [r.tac,r.brand,r.model,r.device_type,r.source,r.verified]);
        count++;
      }
      await client.query("COMMIT");
    } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); }
    res.json({ ok: true, imported: count });
  } catch (e) { res.status(400).json({ error: e.message || "CSV import failed" }); }
});
function parseCsv(input) {
  const lines = input.replace(/^\uFEFF/, "").split(/\r?\n/).filter(x => x.trim());
  if (!lines.length) return [];
  const parseLine = line => { let out=[], cur="", quoted=false; for(let i=0;i<line.length;i++){const c=line[i];if(c==='"'&&line[i+1]==='"'&&quoted){cur+='"';i++;}else if(c==='"'){quoted=!quoted;}else if(c===','&&!quoted){out.push(cur.trim());cur='';}else cur+=c;}out.push(cur.trim());return out; };
  const h=parseLine(lines[0]).map(x=>x.toLowerCase());
  for (const key of ["tac","brand","model"]) if (!h.includes(key)) throw new Error("CSV header must include tac,brand,model");
  const idx=k=>h.indexOf(k);
  return lines.slice(1).map(parseLine).map(a=>({tac:(a[idx("tac")]||"").replace(/\D/g,""),brand:a[idx("brand")]||"",model:a[idx("model")]||"",device_type:a[idx("device_type")]||null,source:a[idx("source")]||"Imported CSV",verified:["true","1","yes"].includes((a[idx("verified")]||"").toLowerCase())}))
    .filter(r=>/^\d{8}$/.test(r.tac)&&r.brand&&r.model);
}
app.get("*", (_req,res)=>res.sendFile(process.cwd()+"/public/index.html"));
app.listen(port,()=>console.log(`Myanmar Phone Checker API listening on ${port}`));
