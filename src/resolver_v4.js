import express from 'express';
import bodyParser from 'body-parser';
import pool from './config.js';

const app = express();
app.use(bodyParser.json());

// 🔹 Schermata di avvio
console.log(`
  🔹═════════════════════════════🔹
  🚀 **Resolver attivo!**
  🌍 **Endpoint:** http://localhost:4000
  📡 **Funzioni disponibili:**
  ✅ Memorizzazione dei DID verificati dall'issuer.
  ✅ Risoluzione dei DID su richiesta di verificatori.
  ✅ Recupero della chiave pubblica tramite DID o nome dell'ente.
  🛠️ **Server pronto per le richieste!**
  🔹═════════════════════════════🔹
`);

app.post('/register-issuer', async (req, res) => {
  console.log("📡 Richiesta di registrazione ricevuta:", req.body);

  const { did, encryptionPublicKey, signingPublicKey, displayName, fiscalCode } = req.body;

  if (!did || !encryptionPublicKey || !signingPublicKey) {
    console.log("❌ Dati mancanti nella richiesta!");
    return res.status(400).json({ error: 'DID o chiavi pubbliche mancanti.' });
  }

  try {
    // 🔍 Controllo se DID esiste già
    const check = await pool.query('SELECT did FROM did_second WHERE did = $1', [did]);

    if (check.rowCount > 0) {
      console.warn(`⚠️ DID ${did} già registrato.`);
      return res.status(409).json({ error: 'DID già presente.' });
    }

    // 💾 Inserimento nella nuova tabella
    await pool.query(
      `INSERT INTO did_second (did, public_key, role, display_name, fiscal_code, metadata)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        did,
        encryptionPublicKey,
        'issuer',
        displayName || null,
        fiscalCode || null,
        JSON.stringify({ signingKey: signingPublicKey })
      ]
    );

    console.log("✅ Issuer registrato correttamente.");
    res.json({ message: 'Issuer registrato!', did });

  } catch (error) {
    console.error('❌ Errore durante la registrazione:', error.message);
    res.status(500).json({ error: 'Errore interno.', details: error.message });
  }
});


app.post('/register-client', async (req, res) => {
  console.log("📡 Registrazione CLIENT ricevuta:", req.body);

  const { did, encryptionPublicKey, signingPublicKey, fiscalCode } = req.body;

  if (!did || !encryptionPublicKey || !signingPublicKey || !fiscalCode) {
    console.log("❌ Dati mancanti nella richiesta client!");
    return res.status(400).json({ error: 'DID, chiavi o codice fiscale mancanti.' });
  }

  try {
    // 🔍 Controllo duplicati sul codice fiscale
    const existing = await pool.query('SELECT id FROM did_second WHERE fiscal_code = $1', [fiscalCode]);

    if (existing.rowCount > 0) {
      console.warn(`⚠️ Il CF ${fiscalCode} è già registrato!`);
      return res.status(409).json({ error: 'Codice fiscale già registrato.' });
    }

    // 💾 Inserimento del client
    await pool.query(
      `INSERT INTO did_second (did, public_key, role, fiscal_code, metadata)
       VALUES ($1, $2, 'client', $3, $4)`,
      [
        did,
        encryptionPublicKey,
        fiscalCode,
        JSON.stringify({ signingKey: signingPublicKey })
      ]
    );

    console.log("✅ Client registrato correttamente nel resolver.");
    res.json({ message: 'Client registrato!', did });

  } catch (error) {
    console.error("❌ Errore durante la registrazione del client:", error.message);
    res.status(500).json({ error: 'Errore interno.', details: error.message });
  }
});

app.get('/resolve/:did', async (req, res) => {
  try {
    const { did } = req.params;
    console.log(`📡 Richiesta di risoluzione per DID: ${did}`);

    // 🔍 Query per cercare nella tabella did_second
    const result = await pool.query(
      'SELECT public_key FROM did_second WHERE did = $1',
      [did]
    );

    console.log("📡 Debug - Risultato query:", result.rows);

    if (result.rows.length === 0) {
      console.log("❌ DID non trovato nella tabella did_second!");
      return res.status(404).json({ error: '❌ DID non trovato nel resolver' });
    }

    const publicKey = result.rows[0].public_key?.trim() || null;

    if (!publicKey) {
      console.log("❌ Chiave pubblica mancante o vuota!");
      return res.status(500).json({ error: '❌ Chiave pubblica non valida nel database' });
    }

    console.log("✅ DID risolto con successo! PublicKey:", publicKey);
    res.json({ did, publicKey });

  } catch (error) {
    console.error("❌ Errore nella risoluzione:", error.stack || error);
    res.status(500).json({ error: '❌ Errore interno del server.' });
  }
});
app.post('/verifier-resolve-request', async (req, res) => {
  const { fiscalCode } = req.body;

  if (!fiscalCode) {
    return res.status(400).json({ error: 'Codice fiscale mancante.' });
  }

  try {
    const result = await pool.query(
      'SELECT did, public_key, metadata FROM did_second WHERE fiscal_code = $1',
      [fiscalCode]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Client non trovato nel resolver.' });
    }

    const { did, public_key, metadata } = result.rows[0];
    const signingKey = metadata?.signingKey || null;

    res.json({
      did,
      encryptionPublicKey: public_key,
      signingPublicKey: signingKey
    });

  } catch (err) {
    console.error('❌ Errore nella risoluzione lato resolver:', err.message);
    res.status(500).json({ error: 'Errore interno del resolver.' });
  }
});
app.get('/signing-key/:did', async (req, res) => {
  const { did } = req.params;

  try {
    const result = await pool.query(
      `SELECT metadata->>'signingKey' AS signing_key FROM did_second WHERE did = $1`,
      [did]
    );

    if (result.rows.length === 0 || !result.rows[0].signing_key) {
      return res.status(404).json({ error: `❌ Signing key non trovata per DID ${did}` });
    }

    const signingKey = result.rows[0].signing_key.trim();

    console.log("✅ Signing key trovata:", signingKey);
    res.json({ signingKey });
  } catch (error) {
    console.error("❌ Errore durante il recupero della signing key:", error.message);
    res.status(500).json({ error: "Errore interno del server" });
  }
});




app.listen(4000, () => console.log('📡 **Il resolver è operativo su http://localhost:4000**'));
