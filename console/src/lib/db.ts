import { Pool } from "pg";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgresql://authclaw:authclaw@localhost:5432/authclaw",
});

export async function query(text: string, params?: unknown[]) {
  return pool.query(text, params);
}

export async function queryWithTenantContext(tenantId: string, text: string, params?: unknown[]) {
  const client = await pool.connect();
  try {
    await client.query("SELECT set_config('app.current_tenant_id', $1, false)", [tenantId]);
    return await client.query(text, params);
  } finally {
    await client.query("SELECT set_config('app.current_tenant_id', '', false)");
    client.release();
  }
}
