/**
 * Zero-trust audit: lists every public table with user_id / owner_id / workspace_id / host_user_id
 * and fails (exit 1) when one has row level security switched off. Also reports which DB roles
 * bypass RLS, because for those roles scope is enforced server-side only.
 *
 *   MIGRATION_URL=... bun scripts/audit-rls.ts
 */
import { Pool } from "@neondatabase/serverless";

const url = process.env["MIGRATION_URL"] ?? process.env["DATABASE_URL"];
if (!url) { console.error("MIGRATION_URL ontbreekt."); process.exit(1); }
const pool = new Pool({ connectionString: url });
const tables = (await pool.query(`select c.relname as t, c.relrowsecurity as rls,
    (select count(*)::int from pg_policy p where p.polrelid = c.oid) as policies,
    array_agg(distinct a.attname::text) as cols
  from pg_class c join pg_namespace n on n.oid = c.relnamespace and n.nspname = 'public'
  join pg_attribute a on a.attrelid = c.oid and not a.attisdropped
    and a.attname in ('user_id','owner_id','workspace_id','host_user_id')
  where c.relkind = 'r' group by c.oid, c.relname, c.relrowsecurity order by c.relname`)).rows as { t: string; rls: boolean; policies: number; cols: string[] }[];
const roles = (await pool.query(`select rolname from pg_roles where rolbypassrls and rolname not like 'pg_%'`)).rows as { rolname: string }[];
await pool.end();

const off = tables.filter((t) => !t.rls);
console.log(`${tables.length} scoped tables; ${off.length} without RLS; ${tables.filter((t) => t.rls && !t.policies).length} deny-by-default (RLS on, no policy).`);
console.log(`Roles bypassing RLS (scope enforced in server code): ${roles.map((r) => r.rolname).join(", ") || "none"}`);
for (const t of off) console.log(`  MISSING RLS: ${t.t} (${t.cols.join(", ")})`);
process.exit(off.length ? 1 : 0);
