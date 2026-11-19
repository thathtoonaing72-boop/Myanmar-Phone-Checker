# Myanmar Phone Checker — Online TAC Database starter

This project connects the V2 dual-IMEI checker to an online PostgreSQL database.

## What is included
- `public/index.html`: V2-style dual IMEI frontend. It validates IMEI checksum in the browser and sends **only the 8-digit TAC** to `/api/tac/:tac`.
- `server.js`: Express API, PostgreSQL lookup, protected CSV bulk-import endpoint.
- `schema.sql`: database table and indexes.

## Important data limitation
No large TAC dataset is bundled. TAC records must come from a source you are licensed/authorized to use (for example, an authorized GSMA data service or a permitted public dataset). Do not assume an arbitrary TAC list is complete or official. Keep the source field and set `verified=true` only after checking the record.

## Deploy (Render/Railway/Fly or another Node host)
1. Create a managed PostgreSQL database.
2. Run `schema.sql` against that database.
3. Deploy this folder as a Node web service.
4. Set environment variables:
   - `DATABASE_URL` = PostgreSQL connection string
   - `TAC_IMPORT_TOKEN` = long random secret used only by the administrator
   - `DATABASE_SSL` = `false` only if your database provider explicitly requires no TLS; otherwise leave unset.
5. Build/start commands:
   - Build: `npm install`
   - Start: `npm start`
6. Add a custom domain and HTTPS using your hosting provider.

## Import TAC CSV
CSV header must include `tac,brand,model`. Optional columns: `device_type,source,verified`.

Example format (the numbers below are placeholders, not real assigned TACs):
```csv
tac,brand,model,device_type,source,verified
12345678,ExampleBrand,Example Model,Phone,Example licensed dataset,false
```

Import with curl (run from your own computer; replace URL and token):
```bash
curl -X POST "https://YOUR-DOMAIN/api/admin/import-csv" \
  -H "Authorization: Bearer YOUR_TAC_IMPORT_TOKEN" \
  -H "Content-Type: text/csv" \
  --data-binary "@tac.csv"
```
The API upserts by TAC, so importing an updated row replaces the prior record for that TAC. Keep your import token private; never put it in frontend JavaScript.

## Test
- `GET /api/health` returns API health and total TAC record count.
- `GET /api/tac/12345678` looks up one TAC.
- The frontend displays “Database မတွေ့ပါ” until matching TAC rows have been imported.

## Security / scope
- Do not upload IMEI lists or account credentials.
- The frontend only sends TAC, not the full IMEI.
- Account-lock and CEIR status are deliberately not fabricated. Integrate them only through official, authorized APIs or portals.
- Add backups, monitoring, authentication for any admin dashboard, and stricter import auditing before production use.
