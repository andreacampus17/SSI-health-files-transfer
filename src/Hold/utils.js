import axios from 'axios';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { verify } from '@noble/ed25519';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
import express from 'express';
const app = express();
app.use(express.json());
import readline from 'readline';

 
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const RESOLVER_DB = path.join(__dirname, 'resolver.json'); // 🔹 Ora funzionerà con moduli ES!
const keysPath = path.join(__dirname, 'keys', 'client_keys');
let entePublicCryptoKey_util=null;
// 🔹 Generazione del DID
const receivedVCs = []; // 🗂 Array globale per memorizzare le VC

export function saveVCToFile(vcData, file_name) {
  try {
    fs.writeFileSync(file_name, JSON.stringify(vcData, null, 2));
    console.log(`✅ VC salvata nel file: ${file_name}`);
    return true; // ✅ Successo nella scrittura
  } catch (error) {
    console.error(`❌ Errore nel salvataggio della VC: ${error.message}`);
    return false; // ❌ Indica un errore
  }
}

function getVCFromFile(filename = "vcData.json") {
  try {
    if (!fs.existsSync(filename)) {
      console.log("❌ Nessun file VC trovato!");
      return null;
    }

    const fileContent = fs.readFileSync(filename, "utf-8");
    const vcData = JSON.parse(fileContent);
    
    //console.log("📜 VC letta dal file:", JSON.stringify(vcData, null, 2));
    return vcData;

  } catch (error) {
    console.error("❌ Errore nella lettura della VC dal file:", error.message);
    return null;
  }
}
export function generateDid() {
  return `did:key:${Math.random().toString(36).substring(2, 15)}`;
}

// 🔹 Registrazione del DID nel resolver
export async function registerDidInResolver(did, controller, publicKey) {
  console.log(`📡 **Registrazione DID nel resolver:** ${did}`);

  let resolverData = [];
  if (fs.existsSync(RESOLVER_DB)) {
    resolverData = JSON.parse(fs.readFileSync(RESOLVER_DB, 'utf8'));
  }

  resolverData.push({ did, controller, publicKey });

  fs.writeFileSync(RESOLVER_DB, JSON.stringify(resolverData, null, 2));
  console.log("✅ **DID registrato con successo!**");
}

// 🔹 Verifica se un DID è registrato prima di emettere una VC
export async function verifyDidExists(did) {
  console.log(`📡 **Verifica se il DID esiste nel resolver:** ${did}`);

  if (!fs.existsSync(RESOLVER_DB)) return false;

  const resolverData = JSON.parse(fs.readFileSync(RESOLVER_DB, 'utf8'));
  return resolverData.some(entry => entry.did === did);
}

// 🔹 Emissione della Verifiable Credential (VC)
export async function issueVerifiableCredential(did, name, surname) {
  console.log(`📡 **Generazione della VC per DID:** ${did}`);

  const vc = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "id": `urn:uuid:${crypto.randomUUID()}`,
    "type": ["VerifiableCredential", "IdentityCredential"],
    "issuer": "did:web:issuer.example.org",
    "issuanceDate": new Date().toISOString(),
    "credentialSubject": {
      "id": did,
      "name": name,
      "surname": surname,
    },
    "proof": {
      "type": "Ed25519Signature2020",
      "created": new Date().toISOString(),
      "proofPurpose": "assertionMethod",
      "verificationMethod": `${did}#key-1`,
      "jws": "eyJhbGciOi..." // 🔹 Simulazione di firma crittografica
    }
  };

  console.log("✅ **VC emessa con successo!**", JSON.stringify(vc, null, 2));
  return vc;
}

// 🔹 Caricamento sicuro dei dati dal file JSON
export function getUserDataFromJson(filename) {
  try {
    const filePath = path.join(__dirname, 'data', filename);
    console.log(`📡 **Leggendo dati dal file JSON: ${filePath}**`);

    if (!fs.existsSync(filePath)) {
      console.error("❌ **Errore: Il file JSON non esiste.**");
      return null;
    }

    const rawData = fs.readFileSync(filePath, 'utf8');
    const { name, surname } = JSON.parse(rawData);

    if (!name || !surname) {
      console.error("❌ **Errore: Nome o cognome mancanti nel file JSON.**");
      return null;
    }

    return { name, surname };
  } catch (err) {
    console.error("❌ **Errore nella lettura del file JSON:**", err.message);
    return null;
  }
}
import crypto from 'crypto';


export function signPayload(payload, privateKeyPem) {
  try {
    const privateKey = crypto.createPrivateKey({
      key: privateKeyPem,
      format: 'pem',
      type: 'pkcs8',
      passphrase: 'La mia frase segreta' // Adatta se necessario
    });

    const sign = crypto.createSign('SHA256');
    sign.update(JSON.stringify(payload));
    sign.end();

    return sign.sign(privateKey, 'base64');
  } catch (error) {
    console.error("❌ Errore nella firma del payload:", error.message);
    return null;
  }
}
export function signPayload_try(payload, privateKeyPem) {
  try {
    // 🔐 Converte la chiave privata da PEM a `KeyObject`
    const privateKey = crypto.createPrivateKey({
      key: privateKeyPem,
      format: 'pem',
      type: 'pkcs8' // Ed25519 usa PKCS#8 per la chiave privata
    });

    // 📝 Firma i dati in UTF-8 nel formato corretto
    return crypto.sign(null, Buffer.from(JSON.stringify(payload), 'utf8'), privateKey);
  } catch (error) {
    console.error("❌ Errore nella firma del payload:", error.message);
    return null;
  }
}




 
export async function viewAcceptedVCs() {
  // ✅ Assicurati che global.vcStorage sia definita
  if (!global.vcStorage || global.vcStorage.length === 0) {
    console.log("✅ Nessuna VC ricevuta.");
    return;
  }

  console.log("📜 LISTA DELLE VC ACCETTATE:");
  global.vcStorage.forEach((vc, index) => {
    console.log(`🔢 ${index + 1} - DID Issuer: ${vc.issuer || "N/D"}`);
    console.log(`📜 Contenuto VC: ${JSON.stringify(vc, null, 2)}`);
    console.log("────────────────────────────");
  });
}


export function askServerPort() {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    rl.question("🔹 Inserisci la porta del server: ", (serverPort) => {
      rl.close();
      resolve(serverPort);
    });
  });
}
import net from "net";

export async function findAvailableClientPort(startPort = 5000) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(startPort, () => {
      server.close(() => resolve(startPort)); // 🔹 La porta è libera!
    });
    server.on("error", () => resolve(findAvailableClientPort(startPort + 1))); // 🔹 Porta occupata, prova la successiva
  });
}


export async function receiveAndDecryptMessageFromServer(encryptedMessage, privateKeyClient, entePublicCryptoKey) {
  try {
    console.log("🔎 CLIENT - Tipo di encryptedMessage:", typeof encryptedMessage);
    console.log("🔎 CLIENT - Contenuto encryptedMessage:", encryptedMessage);
    console.log("🔎 CLIENT - Tipo di privateKeyClient:", typeof privateKeyClient);
    console.log("🔎 CLIENT - Contenuto privateKeyClient:", privateKeyClient);
    console.log("🔎 CLIENT - Tipo di entePublicCryptoKey:", typeof entePublicCryptoKey);
    console.log("🔎 CLIENT - Contenuto entePublicCryptoKey:", entePublicCryptoKey);
    console.log("🔎 CLIENT - Lunghezza chiave privata (base64 o hex):", privateKeyClient.length);
    entePublicCryptoKey_util=entePublicCryptoKey;

    

// Controlla la lunghezza dopo la conversione


    if (!encryptedMessage || !privateKeyClient || !entePublicCryptoKey) {
      throw new Error("❌ Dati mancanti per la decriptazione!");
    }

    // 📌 Decodifica Base64 → Buffer
    const nonce = Buffer.from(encryptedMessage.nonce, "base64");
    const ciphertext = Buffer.from(encryptedMessage.ciphertext, "base64");
    const clientPrivateCryptoKeyBytes = Buffer.from(privateKeyClient, "hex");

    const entePublicCryptoKeyBytes = Buffer.from(entePublicCryptoKey, "base64"); // ✅ Corretta!
    console.log("🔎 CLIENT - Lunghezza chiave privata dopo conversione:", clientPrivateCryptoKeyBytes.length);

    // 📌 Decripta il messaggio usando NaCl
    const decryptedMessageBytes = nacl.box.open(
      ciphertext,
      nonce,
      entePublicCryptoKeyBytes, // ✅ Chiave pubblica dell'ente
      clientPrivateCryptoKeyBytes // 🔐 Chiave privata del client per decriptare
    );

    if (!decryptedMessageBytes) {
      throw new Error("❌ Errore nella decriptazione del messaggio!");
    }

    // 📌 Convertiamo i bytes in testo leggibile
    const decryptedMessage = naclUtil.encodeUTF8(decryptedMessageBytes);
    console.log("✅ CLIENT - Messaggio decifrato:", decryptedMessage);

    return {
      decryptedMessage,
      status: "✅ Messaggio ricevuto e decifrato!"
    };

  } catch (error) {
    console.error("❌ Errore durante la decriptazione:", error.message);
    return { error: error.message };
  }
}


export function generateClientKeys() {
  console.log("🚀 Generazione delle chiavi...");

  // 🔐 Chiavi di firma (Ed25519)
  const signingKeys = nacl.sign.keyPair();
  const publicSigningKey = Buffer.from(signingKeys.publicKey).toString('hex');
  const privateSigningKey = Buffer.from(signingKeys.secretKey).toString('hex');

  // 🔐 Chiavi di crittografia (X25519)
  const encryptionKeys = nacl.box.keyPair();
  const publicEncryptionKey = Buffer.from(encryptionKeys.publicKey).toString('hex');
  const privateEncryptionKey = Buffer.from(encryptionKeys.secretKey).toString('hex');

  console.log("✅ Chiavi generate correttamente!");
  
  return {
    signingKeys: {
      publicKey: publicSigningKey,
      privateKey: privateSigningKey
    },
    encryptionKeys: {
      publicKey: publicEncryptionKey,
      privateKey: privateEncryptionKey
    }
  };
}
export function loadKeys(controller) {
  console.log(`📂 Caricamento chiavi per: ${controller}`);

  const keys = {
    encryptionKeys: {
      publicKey: fs.readFileSync(`${keysPath}/${controller}_x25519_public_crypto.txt`, 'utf8'),
      privateKey: fs.readFileSync(`${keysPath}/${controller}_x25519_private_crypto.txt`, 'utf8')
    },
    signingKeys: {
      publicKey: fs.readFileSync(`${keysPath}/${controller}_ed25519_public_sign.txt`, 'utf8'),
      privateKey: fs.readFileSync(`${keysPath}/${controller}_ed25519_private_sign.txt`, 'utf8')
    }
  };

  console.log("✅ Chiavi caricate con successo!");
  return keys;
}
export function saveKeys(controller) {
  console.log(`🚀 Generazione delle chiavi per: ${controller}`);

  // 🔐 Genera le chiavi
  const signingKeys = nacl.sign.keyPair();
  const encryptionKeys = nacl.box.keyPair();

  const keys = {
    signingKeys: {
      publicKey: Buffer.from(signingKeys.publicKey).toString('hex'),
      privateKey: Buffer.from(signingKeys.secretKey).toString('hex')
    },
    encryptionKeys: {
      publicKey: Buffer.from(encryptionKeys.publicKey).toString('hex'),
      privateKey: Buffer.from(encryptionKeys.secretKey).toString('hex')
    }
  };

  // 🔎 Salva le chiavi nei file dentro `keys/client_keys`
  fs.writeFileSync(`${keysPath}/${controller}_x25519_public_crypto.txt`, keys.encryptionKeys.publicKey);
  fs.writeFileSync(`${keysPath}/${controller}_x25519_private_crypto.txt`, keys.encryptionKeys.privateKey);
  fs.writeFileSync(`${keysPath}/${controller}_ed25519_public_sign.txt`, keys.signingKeys.publicKey);
  fs.writeFileSync(`${keysPath}/${controller}_ed25519_private_sign.txt`, keys.signingKeys.privateKey);

  console.log(`✅ Chiavi salvate correttamente in ${keysPath}`);
}





