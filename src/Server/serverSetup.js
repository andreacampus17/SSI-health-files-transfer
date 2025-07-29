import express from 'express';
import fs from 'fs';
import path from 'path';
import nacl from 'tweetnacl';
import { dirname } from 'path';
import { fileURLToPath } from 'url';


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class ServerSetup {
  constructor(rl,app) {
    this.app = app
    this.app.use(express.json());

    this.rl = rl; // 🔹 Instanza di readline ricevuta dal ServerManager

    this.serverPort = null;
    this.issuerDid = null;
    this.controller = null;

    this.entePublicCryptoKey = null;
    this.entePrivateCryptoKey = null;
    this.entePublicSignKey = null;
    this.entePrivateSignKey = null;
    this.verifier_accepted_requests=[];
    this.fiscslCode=null;
    this.keyspath = path.resolve(__dirname, 'keys');
    this.issuerFilesPath=null;
    this.verifierFilesPath=null;
    

  }
createIssuerFilesFolder(prefix, controller) {
  const sanitizedPrefix = prefix.replace(/[^a-zA-Z0-9_-]/g, "_");
  const sanitizedController = controller.replace(/[^a-zA-Z0-9_-]/g, "_");

  const folderName = `${sanitizedPrefix}_${sanitizedController}`;
  const baseFolder = path.join(__dirname, "IssuerFiles"); // cartella principale
  const folderPath = path.join(baseFolder, folderName);

  if (!fs.existsSync(folderPath)) {
    fs.mkdirSync(folderPath, { recursive: true });
    console.log(`📁 Cartella creata: ${folderPath}`);
  } else {
    console.log(`ℹ️ Cartella già esistente: ${folderPath}`);
  }

  return folderPath;
}

createVerifierFilesFolder(prefix, controller) {
  const sanitizedPrefix = prefix.replace(/[^a-zA-Z0-9_-]/g, "_");
  const sanitizedController = controller.replace(/[^a-zA-Z0-9_-]/g, "_");

  const folderName = `${sanitizedPrefix}_${sanitizedController}`;
  const baseFolder = path.join(__dirname, "VerifierFiles"); // cartella principale
  const folderPath = path.join(baseFolder, folderName);

  if (!fs.existsSync(folderPath)) {
    fs.mkdirSync(folderPath, { recursive: true });
    console.log(`📁 Cartella creata: ${folderPath}`);
  } else {
    console.log(`ℹ️ Cartella già esistente: ${folderPath}`);
  }

  return folderPath;
}

createFolderForClient(prefix, parentPath) {
  const sanitizedPrefix = prefix.replace(/[^a-zA-Z0-9_-]/g, "_");
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-"); // per evitare collisioni
  const folderName = `${sanitizedPrefix}_${timestamp}`;
  const folderPath = path.join(parentPath, folderName);

  if (!fs.existsSync(folderPath)) {
    fs.mkdirSync(folderPath, { recursive: true });
    console.log(`📁 Cartella client creata: ${folderPath}`);
  } else {
    console.log(`ℹ️ Cartella client già esistente (cosa rara): ${folderPath}`);
  }

  return folderPath;
}
  async startServer(did, controller, cFiscale) {
    this.issuerDid = did;
    this.controller = controller;
    this.fiscalCode=cFiscale;

    this.serverPort = await this.askServerPort(); // 🔹 Ora usiamo `rl` passata
    this.issuerFilesPath = this.createIssuerFilesFolder("issuer", this.controller);
    this.verifierFilesPath = this.createVerifierFilesFolder("verifier", this.controller);
    return new Promise((resolve) => {
        this.app.listen(this.serverPort, async () => {
            console.log(`🚀 Server avviato su http://localhost:${this.serverPort}`);
            console.log(`✅ DID ricevuto: ${this.issuerDid}`);
            console.log(`✅ Controller ricevuto: ${this.controller}`);

            const { encryptionKeys, signingKeys } = this.generateKeys();
            await this.registerDID(encryptionKeys, signingKeys,cFiscale);

            resolve("✅ Server avviato correttamente!"); // 🔹 Restituisce un valore alla chiamata

        });
    });
}


  askServerPort() {
    return new Promise((resolve) => {
      this.rl.question("🔹 Inserisci la porta su cui il server deve ascoltare: ", (port) => {
        resolve(parseInt(port));
      });
    });
  }

generateKeys() {
  console.log(`🔑 Generazione chiavi per DID: ${this.issuerDid}`);

  const encryptionKeys = nacl.box.keyPair();
  const signingKeys = nacl.sign.keyPair();

  const encodedEncryptionKeys = {
    publicKey: Buffer.from(encryptionKeys.publicKey).toString('base64'),
    privateKey: Buffer.from(encryptionKeys.secretKey).toString('base64'),
  };

  const encodedSigningKeys = {
    publicKey: Buffer.from(signingKeys.publicKey).toString('base64'),
    privateKey: Buffer.from(signingKeys.secretKey).toString('base64'),
  };

  console.log("📦 Chiavi di crittografia (X25519):");
  console.log("🔐 Public  (base64):", encodedEncryptionKeys.publicKey);
  console.log("🔐 Private (base64):", encodedEncryptionKeys.privateKey);

  console.log("✍️ Chiavi di firma (Ed25519):");
  console.log("🖋️ Public  (base64):", encodedSigningKeys.publicKey);
  console.log("🖋️ Private (base64):", encodedSigningKeys.privateKey);

  return {
    encryptionKeys: encodedEncryptionKeys,
    signingKeys: encodedSigningKeys
  };
}


async registerDID(encryptionKeys, signingKeys, fiscalCode) {
  const RESOLVER_URL = 'http://localhost:4000/register-issuer';

  try {
    const response = await fetch(RESOLVER_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        did: this.issuerDid,
        controller: this.controller,
        encryptionPublicKey: encryptionKeys.publicKey,
        signingPublicKey: signingKeys.publicKey,
        displayName: this.controller, // usiamo il controller come nome leggibile
        fiscalCode: fiscalCode || null
      })
    });

    if (response.status === 409) {
      console.warn(`⚠️ DID "${this.issuerDid}" già registrato! Recupero chiavi salvate...`);
      await this.loadExistingKeys();
    } else if (response.ok) {
      console.log("✅ DID registrato con successo!");
      this.saveKeys(encryptionKeys, signingKeys);
    } else {
      // 🔍 Leggo il messaggio d’errore dal backend per capire cosa è andato storto
      const errText = await response.text();
      console.error("❌ Errore nella registrazione del DID!", errText);
    }

  } catch (error) {
    console.error("❌ Errore durante la registrazione del DID:", error.message);
  }
}



  saveKeys(encryptionKeys, signingKeys) {
    this.entePublicCryptoKey = encryptionKeys.publicKey;
    this.entePrivateCryptoKey = encryptionKeys.privateKey;
    this.entePublicSignKey = signingKeys.publicKey;
    this.entePrivateSignKey = signingKeys.privateKey;

    fs.writeFileSync(`${this.keyspath}/${this.controller}_x25519_public_ente.txt`, this.entePublicCryptoKey);
    fs.writeFileSync(`${this.keyspath}/${this.controller}_x25519_private_ente.txt`, this.entePrivateCryptoKey);
    fs.writeFileSync(`${this.keyspath}/${this.controller}_ed25519_public_ente.txt`, this.entePublicSignKey);
    fs.writeFileSync(`${this.keyspath}/${this.controller}_ed25519_private_ente.txt`, this.entePrivateSignKey);

    console.log("✅ Chiavi salvate correttamente!");
  }

  async loadExistingKeys() {
    try {
      this.entePublicCryptoKey = fs.readFileSync(`${this.keyspath}/${this.controller}_x25519_public_ente.txt`, 'utf8');
      this.entePrivateCryptoKey = fs.readFileSync(`${this.keyspath}/${this.controller}_x25519_private_ente.txt`, 'utf8');
      this.entePublicSignKey = fs.readFileSync(`${this.keyspath}/${this.controller}_ed25519_public_ente.txt`, 'utf8');
      this.entePrivateSignKey = fs.readFileSync(`${this.keyspath}/${this.controller}_ed25519_private_ente.txt`, 'utf8');

      console.log("✅ Chiavi esistenti caricate!");
    } catch (error) {
      console.error("❌ Errore nel caricamento delle chiavi esistenti:", error.message);
    }
  }
listClientFiles(prefix, parentFolderPath) {
  console.log("📥 [listClientFiles] Chiamata con:");
  console.log("→ prefix:", prefix);
  console.log("→ parentFolderPath:", parentFolderPath);

  const matchedFolder = this.trovaCartellaDaPrefisso(prefix, parentFolderPath);
  console.log("🔎 matchedFolder:", matchedFolder);

  if (!matchedFolder) {
    console.warn(`⚠️ Nessuna cartella trovata con prefisso: ${prefix}`);
    return [];
  }

  const clientFolderPath = path.join(parentFolderPath, matchedFolder);
  console.log("📁 Path completo client:", clientFolderPath);

  const files = fs.readdirSync(clientFolderPath, { withFileTypes: true })
    .filter(entry => entry.isFile())
    .map(entry => entry.name);

  console.log("📄 File trovati:", files);

  return { clientFiles: files, matchedFolder }; // 💥 fix: ritorna clientFiles, non solo files
}

 trovaCartellaDaPrefisso(prefix, parentPath) {
  const cartelle = fs.readdirSync(parentPath, { withFileTypes: true })
    .filter(entry => entry.isDirectory() && entry.name.startsWith(prefix))
    .map(entry => entry.name);

  return cartelle[0] || null;
}


  getPublicCryptoKey() {
    return this.entePublicCryptoKey;
  }

  getPrivateCryptoKey() {
    return this.entePrivateCryptoKey;
  }

  getPublicSignKey() {
    return this.entePublicSignKey;
  }

  getPrivateSignKey() {
    return this.entePrivateSignKey;
  }
}
