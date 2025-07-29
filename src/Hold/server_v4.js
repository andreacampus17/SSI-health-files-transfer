import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import fs from 'fs';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
import {encryptAndSendToClient,findAvailablePort} from './utilsIssuer.js'
import { serverMenu } from './serverMenu.js';
import axios from 'axios';

const app = express();
app.use(express.json());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
//const privateSignKey=fs.readFileSync(path.join(__dirname, 'private_sign_key_ente_3.txt'), 'utf8');
// Legge la chiave privata RSA dell'ente (file PEM)
//const privateKeyEnte = fs.readFileSync(path.join(__dirname, 'private_key_ente.pem'), 'utf8');
let entePrivateSignKey=0;
let entePublicSignKey=0;
let entePrivateCryptoKey=0;
let entePublicCryptoKey=0;
let clientPublicCryptoKeyBytes=0;
const keyspath = path.resolve(__dirname, 'keys');
let issuerDid=null;
let registrationRequests = []; // 🗂 Array per salvare le richieste
let acceptedRequests=[];
let globalClientDidDocument = null; // 🔹 Variabile globale per il DID Document
let serverPort = null;
let clientPort = null;

let serverListeningPort = null;
let clientAssignedPort = null;

export function setServerListeningPort(port) {
  serverListeningPort = port;
}

export function setClientAssignedPort(port) {
  clientAssignedPort = port;
}

export function getRegisteredPorts() {
  return { serverListeningPort, clientAssignedPort };
}


export function getEntePublicCryptoKey()
{
  return entePublicCryptoKey;
}
export function getEntePrivateCryptoKey()
{
  return entePrivateCryptoKey;
}
app.post('/receive-message', async (req, res) => {
  try {
    const { encryptedMessage, signature, senderDID, didDocument} = req.body;

    if (!encryptedMessage || !senderDID || !signature || !didDocument) {
      return res.status(400).json({ error: "❌ Dati mancanti nella richiesta!" });
    }

    // 📌 Salva l'intero payload in memoria
    registrationRequests.push({
      senderDID,
      didDocument,
      encryptedMessage,
      signature,
      clientPort,
      timestamp: new Date().toISOString()
    });

    console.log("✅ SERVER - Registrazione completa salvata:", senderDID);
    console.log("🗂 Contenuto di registrationRequests:", JSON.stringify(registrationRequests, null, 2));
    console.log("Il messaggio criptato è: ",encryptedMessage);
    serverMenu();
    return res.json({ message: "✅ Richiesta di registrazione ricevuta!" });

  } catch (error) {
    console.error("❌ Errore interno del server:", error);
    res.status(500).json({ error: "❌ Errore interno del server!" });
    return serverMenu();
  }
  
});

export async function viewRegistrations() {
  if (registrationRequests.length === 0) {
    console.log("✅ Nessuna richiesta di registrazione.");
    return [];
  }

  console.log("📜 SERVER - Richieste di registrazione ricevute:");
  


  return registrationRequests.map((req, index) => {
  try {
    console.log("📝 DID Document ricevuto:", JSON.stringify(req.didDocument, null, 2));
    globalClientDidDocument= req.didDocument;

    if (!req.encryptedMessage?.nonce || !req.encryptedMessage?.ciphertext) {
      console.error("❌ Messaggio crittografato mancante!");
      throw new Error("❌ Messaggio crittografato mancante!");
    }

    if (!req.signature) {
      console.error("❌ Firma digitale mancante!");
      throw new Error("❌ Firma digitale mancante!");
    }

    const nonce = Buffer.from(req.encryptedMessage.nonce, "base64");
    const ciphertext = Buffer.from(req.encryptedMessage.ciphertext, "base64");
    const entePrivateCryptoKeyBytes = Uint8Array.from(Buffer.from(entePrivateCryptoKey, "base64"));

    const keyAgreementEntry = req.didDocument?.didDocument?.keyAgreement?.find(entry => entry.id?.includes("key-encryption"));
    if (!keyAgreementEntry?.publicKeyHex?.data) {
      console.error("❌ Chiave pubblica del client non trovata!");
      throw new Error("❌ Chiave pubblica del client non trovata!");
    }
    console.log("🔎 SERVER - Nonce (Base64 → Buffer):", nonce);
    console.log("🔎 SERVER - Ciphertext (Base64 → Buffer):", ciphertext);
    console.log("🔎 SERVER - entePrivateCryptoKeyBytes (Base64 → Uint8Array):", entePrivateCryptoKeyBytes);


    const clientPublicCryptoKeyBytes = Uint8Array.from(keyAgreementEntry.publicKeyHex.data);
    console.log("🔎 chiave pubblica del client convertita Uint8Array):", clientPublicCryptoKeyBytes);
    // 🔓 Decriptiamo il messaggio
    const decryptedMessageBytes = nacl.box.open(ciphertext, nonce, clientPublicCryptoKeyBytes, entePrivateCryptoKeyBytes);

    if (!decryptedMessageBytes) {
      console.error("❌ Errore nella decriptazione!");
      throw new Error("❌ Errore nella decriptazione!");
    }

    const decryptedMessage = naclUtil.encodeUTF8(decryptedMessageBytes);

    

    const verificationMethod = req.didDocument.didDocument.verificationMethod.find(
      method => method.type === "Ed25519VerificationKey2018" && method.publicKeyHex?.data
    );
    // 📌 Verifica firma digitale 
    console.log("🔎 SERVER - Contenuto di verificationMethod:", JSON.stringify(req.didDocument.didDocument.verificationMethod, null, 2));
    console.log("🔎 SERVER - Chiave pubblica estratta:", verificationMethod?.publicKeyHex);
    if (!verificationMethod) {
    console.error("❌ Nessuna chiave pubblica di firma trovata!");
    throw new Error("❌ Nessuna chiave pubblica di firma trovata!");
    }

    // 🔎 Estrai la chiave correttamente
    const publicKeySignBytes = Uint8Array.from(verificationMethod.publicKeyHex.data);

    console.log("🔎 SERVER - Chiave pubblica estratta (Hex):", Buffer.from(publicKeySignBytes).toString('hex'));
    console.log("🔎 SERVER - Lunghezza della chiave pubblica:", publicKeySignBytes.length);

    const signatureBytes = Buffer.from(req.signature, "base64");
    const messageBytes = naclUtil.decodeUTF8(decryptedMessage);

    const isValidSignature = nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeySignBytes);
    console.log("Firma valida!",isValidSignature);
    return {
      number: index + 1,
      senderDID: req.senderDID,
      timestamp: req.timestamp,
      decryptedMessage,
      signatureValid: isValidSignature ? "✅ Firma valida" : "❌ Firma non valida!"
    };

  } catch (error) {
    console.error("❌ Errore durante la decriptazione o verifica firma:", error.message);
    return { 
      number: index + 1,
      senderDID: req.senderDID, 
      timestamp: req.timestamp, 
      error: "❌ Errore nella decriptazione o firma non verificabile!" 
    };
  }
});
}

export async function acceptOrRejectRequest(number, action) {
  if (number < 1 || number > registrationRequests.length) {
    console.log("❌ Numero richiesta non valida!");
    return;
  }

  const request = registrationRequests[number - 1];

  if (action === "accept") {
    acceptedRequests.push(request);
    console.log(`✅ Richiesta ${number} accettata!`);

    // 🔹 Generiamo e inviamo la VC al client
    const encryptedVC = await processRegistrationRequest(request);

    //console.log("📤 VC inviata al client:", encryptedVC);
    
  } else if (action === "reject") {
    rejectedRequests.push(request);
    console.log(`❌ Richiesta ${number} rifiutata!`);
  }

  // 🔹 Rimuoviamo la richiesta dall’elenco principale
  registrationRequests.splice(number - 1, 1);
}

async function processRegistrationRequest(request) {
  try {
    console.log(`🚀 Elaborazione richiesta DID: ${request.senderDID}`);

    // 📌 Recupera le chiavi dal DID Document
    const keyAgreementEntry = globalClientDidDocument?.didDocument?.keyAgreement?.find(entry => entry.id?.includes("key-encryption"));
    const clientPublicCryptoKeyBytes = Uint8Array.from(keyAgreementEntry.publicKeyHex.data);    
    const issuerPublicSignKeyBytes = Buffer.from(entePublicSignKey, "base64");
    const issuerPrivateSignKeyBytes = Buffer.from(entePrivateSignKey, "base64");
    const issuerPrivateCryptoKey = Buffer.from(entePrivateCryptoKey, "base64");

    // 📌 Dati per la VC
    globalClientDidDocument.didDocument.keyAgreement
    const responseData = { message: "✅ Registrazione accettata!, questi sono i tuoi dati" };
    console.log("Chiave pubblica Ente: ",entePublicCryptoKey);

    // 🔹 Generazione e crittografia della VC
    const encryptedVC = await encryptAndSendToClient(
      "enteName",
      issuerDid,
      request.senderDID,
      clientPublicCryptoKeyBytes,
      issuerPublicSignKeyBytes,
      issuerPrivateSignKeyBytes,
      issuerPrivateCryptoKey,
      entePublicCryptoKey,
      responseData
    );
    console.log("Questa è la chiave pubblica prima di metterla nel messaggio: ",entePublicCryptoKey);

    console.log("✅ VC generata e crittografata:", encryptedVC);

    let clientResponse;
    // 📤 **Invia la VC al client locale**
    const clientURL = `http://localhost:${getRegisteredPorts().clientAssignedPort}`;
 // 🔹 URL del client locale

    try {
      console.log("📤 Sto inviando la VC al client...");
      clientResponse = await axios.post(`${clientURL}/receive-server-vc`, encryptedVC);
      console.log("✅ VC inviata al client! Risposta:", clientResponse.data.message);
    } catch (error) {
      console.error("❌ Errore nell'invio della VC al client:", error.message);
    }

    console.log("📤 VC inviata al client locale! Risposta:", clientResponse?.data);
    return serverMenu();

  } catch (error) {
    console.error("❌ Errore nell'elaborazione della richiesta:", error.message);
  }
}









   



export async function startServer(did, controller) {
  
  const RESOLVER_URL = 'http://localhost:4000/register'; // 🔹 Registra DID e chiavi
  console.log(`📂 Percorso delle chiavi: ${keyspath}`);
  const SERVER_PORT = await findAvailablePort(3000); // 🔹 Cerca una porta libera a partire da 3000
  app.listen(SERVER_PORT, async () => {
    console.log(`🚀 Server in ascolto su http://localhost:3000`);
    console.log(`✅ DID ricevuto: ${did}`);
    console.log(`✅ Controller ricevuto: ${controller}`);

    // 🔹 Genera chiavi per crittografia e firma
    const { encryptionKeys, signingKeys } = generateKeys(did, controller);

    try {
      console.log("🔎 Inviando dati al resolver...");
      const response = await fetch(RESOLVER_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          did,
          controller, // 🔹 Aggiunto il controller alla POST
          encryptionPublicKey: encryptionKeys.publicKey,
          signingPublicKey: signingKeys.publicKey
        })
      });

      if (response.status === 409) {
        console.warn(`⚠️ DID "${did}" già registrato! Recupero le chiavi salvate...`);

        try {
          // 🔎 Controlla se i file esistono prima di leggerli
          const filesToCheck = [
            `${keyspath}/${controller}_x25519_public.txt`,
            `${keyspath}/${controller}_x25519_private.txt`,
            `${keyspath}/${controller}_ed25519_public.txt`,
            `${keyspath}/${controller}_ed25519_private.txt`
          ];

          const missingFiles = filesToCheck.filter(file => !fs.existsSync(file));
          if (missingFiles.length > 0) {
            console.warn(`⚠️ Alcuni file di chiavi mancanti: ${missingFiles.join(", ")}. Creazione nuovi file...`);

            // 🔹 Salva le chiavi in file se mancanti
            fs.writeFileSync(`${keyspath}/${controller}_x25519_public.txt`, encryptionKeys.publicKey);
            fs.writeFileSync(`${keyspath}/${controller}_x25519_private.txt`, encryptionKeys.privateKey);
            fs.writeFileSync(`${keyspath}/${controller}_ed25519_public.txt`, signingKeys.publicKey);
            fs.writeFileSync(`${keyspath}/${controller}_ed25519_private.txt`, signingKeys.privateKey);
          }

          // 🔎 Carica le chiavi esistenti dai file
          entePublicCryptoKey = fs.readFileSync(`${keyspath}/${controller}_x25519_public.txt`, 'utf8');
          entePrivateCryptoKey = fs.readFileSync(`${keyspath}/${controller}_x25519_private.txt`, 'utf8');
          entePublicSignKey = fs.readFileSync(`${keyspath}/${controller}_ed25519_public.txt`, 'utf8');
          entePrivateSignKey = fs.readFileSync(`${keyspath}/${controller}_ed25519_private.txt`, 'utf8');

          console.log("✅ Chiavi esistenti caricate correttamente!");
          return serverMenu();

        } catch (fileError) {
          console.error("❌ Errore nel recupero delle chiavi:", fileError.message);
          return serverMenu();
        }

      } else if (!response.ok) {
        console.log("Errore nella registrazione");
          return serverMenu();
      } else {
        console.log("✅ DID, controller e chiavi registrati con successo!");
        entePublicCryptoKey = encryptionKeys.publicKey;
        entePrivateCryptoKey = encryptionKeys.privateKey;
        entePublicSignKey = signingKeys.publicKey;
        entePrivateSignKey = signingKeys.privateKey;

        fs.writeFileSync(`${keyspath}/${controller}_x25519_public.txt`, entePublicCryptoKey);
        fs.writeFileSync(`${keyspath}/${controller}_x25519_private.txt`, entePrivateCryptoKey);
        fs.writeFileSync(`${keyspath}/${controller}_ed25519_public.txt`, entePublicSignKey);
        fs.writeFileSync(`${keyspath}/${controller}_ed25519_private.txt`, entePrivateSignKey);
        console.log("🔎 SERVER - Chiavi caricate dai file:");

        console.log("🔎 SERVER - Chiavi caricate dai file:");

        const serverPublicKeyBuffer = Buffer.from(entePublicCryptoKey, 'base64');
        console.log("🔎 X25519 Pubblica (Buffer):", serverPublicKeyBuffer);
        console.log("🔎 X25519 Pubblica - Lunghezza:", serverPublicKeyBuffer.length);

        const serverPrivateKeyBuffer = Buffer.from(entePrivateCryptoKey, 'base64');
        console.log("🔎 X25519 Privata (Buffer):", serverPrivateKeyBuffer);
        console.log("🔎 X25519 Privata - Lunghezza:", serverPrivateKeyBuffer.length);

        const serverSignPublicKeyBuffer = Buffer.from(entePublicSignKey, 'base64');
        console.log("🔎 Ed25519 Pubblica (Buffer):", serverSignPublicKeyBuffer);
        console.log("🔎 Ed25519 Pubblica - Lunghezza:", serverSignPublicKeyBuffer.length);

        const serverSignPrivateKeyBuffer = Buffer.from(entePrivateSignKey, 'base64');
        console.log("🔎 Ed25519 Privata (Buffer):", serverSignPrivateKeyBuffer);
        console.log("🔎 Ed25519 Privata - Lunghezza:", serverSignPrivateKeyBuffer.length);

        issuerDid=did;
        return serverMenu();
      }

    } catch (error) {
      console.error("❌ Errore generale nella registrazione:", error.message);
      return serverMenu();
    }
  });
}




function generateKeys(did,controller) {
  console.log(`🔑 Generazione chiavi con NaCl per DID: ${did}`);

  // **1️⃣ Crittografia (X25519)**
  const encryptionKeyPair = nacl.box.keyPair();
  const encryptionKeys = {
    publicKey: Buffer.from(encryptionKeyPair.publicKey).toString('base64'),
    privateKey: Buffer.from(encryptionKeyPair.secretKey).toString('base64'),
  };

  // **2️⃣ Firma digitale (Ed25519)**
  const signingKeyPair = nacl.sign.keyPair();
  const signingKeys = {
    publicKey: Buffer.from(signingKeyPair.publicKey).toString('base64'),
    privateKey: Buffer.from(signingKeyPair.secretKey).toString('base64'),
  };

  

  console.log("🚀 Tutte le chiavi sono state generate: ");

console.log("🔎 SERVER - Chiavi di crittografia generate:");
console.log("🔎 Pubblica X25519:", encryptionKeys.publicKey);
console.log("🔎 Privata X25519:", encryptionKeys.privateKey);

console.log("🔎 SERVER - Chiavi di firma generate:");
console.log("🔎 Pubblica Ed25519:", signingKeys.publicKey);
console.log("🔎 Privata Ed25519:", signingKeys.privateKey);


  return { encryptionKeys, signingKeys }; // 🔹 Ritorna le chiavi per eventuale uso immediato
}

