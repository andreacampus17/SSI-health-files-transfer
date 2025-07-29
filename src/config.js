import { Pool } from 'pg';

const pool = new Pool({
  user: 'diduser',
  host: 'localhost',
  database: 'did_ledger',
  password: 'Ciaociao123',
  port: 5432,
});

export default pool; // ✅ Esporta `pool` correttamente
