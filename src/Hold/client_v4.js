import axios from 'axios';
import readline from 'readline';
import { createAgent } from '@veramo/core';
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager';
import { KeyManagementSystem } from '@veramo/kms-local';
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager';
import { KeyDIDProvider, getDidKeyResolver } from '@veramo/did-provider-key';
import { DIDResolverPlugin } from '@veramo/did-resolver';
import { Resolver } from 'did-resolver';
import crypto from 'crypto';
import {signPayload,receiveAndDecryptMessageFromServer,generateClientKeys,loadKeys,saveKeys,saveVCToFile,viewAcceptedVCs,askServerPort} from'./utils.js'
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
askServerPort()
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
let enteCryptoPublicKey=null;
const app = express();
app.use(express.json());
// 📂 Definisce il percorso corretto per i file dentro `keys/client_keys`
const resolverURL = 'http://localhost:4000';

let enteUrl=null;
let identity = null;
let agent = null;
let key = null;
 
// Leggere la chiave pubblica
import fs from 'fs';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const keysPath = path.join(__dirname, 'keys', 'client_keys');
let clientPrivateCryptoKey=null;
let clientPublicCryptoKey=null;
let clientPrivateSignKey=null;
let clientPublicSignKey=null;
global.vcStorage = []; // da dichiarare una sola volta all’avvio
app.post("/test-endpoint", (req, res) => {
  console.log("📥 TEST - Ho ricevuto una richiesta! Ecco i dati:");
  console.log(req.body);

  res.json({ message: "✅ TEST - Il client ha ricevuto correttamente la richiesta!" });
});

app.post("/receive-server-vc", (req, res) => {
  console.log("richiesta ricevuta!!");
  try {
    console.log("📨 Richiesta ricevuta!");
    processReceivedVC(req.body, res);
  } catch (error) {
    console.error("❌ Errore nel salvataggio della VC:", error.message);
    res.status(500).json({ error: "❌ Errore interno del server!" });
  }
});
function hexToUint8Array(hex) {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex string");
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    arr[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return arr;
}

let SERVER_PORT = null;
let CLIENT_PORT = null;

export function setServerPort(port) {
  SERVER_PORT = port;
}

export function setClientPort(port) {
  CLIENT_PORT = port;
}

export function getPorts() {
  if (SERVER_PORT === null || CLIENT_PORT === null) {
    console.warn("⚠️ Attenzione: Le porte non sono state inizializzate!");
    return { serverPort: SERVER_PORT || "❌ Non inizializzato", clientPort: CLIENT_PORT || "❌ Non inizializzato" };
  }
  return { serverPort: SERVER_PORT, clientPort: CLIENT_PORT };
}


function processReceivedVC(vcData, res) {
  try {
    console.log("📥 Richiesta ricevuta per la VC crittografata!");

    // Stampo tutto il pacchetto ricevuto raw
    console.log("📦 Dati VC ricevuti (raw):", JSON.stringify(vcData, null, 2));

    // Decodifica i dati dal formato Base64
    console.log("🔑 Decodifica Base64 delle componenti...");

    try {
      const encryptedMessageBytes = naclUtil.decodeBase64(vcData.ciphertext);
      console.log("🔐 encryptedMessageBytes:", encryptedMessageBytes);

      const nonce = naclUtil.decodeBase64(vcData.nonce);
      console.log("🧂 nonce:", nonce);

      const issuerPublicCryptoKeyBytes = Buffer.from(vcData.issuerPublicCryptoKey, 'base64');

      const clientPrivateCryptoKeyBytes = hexToUint8Array(clientPrivateCryptoKey);

      console.log("🔑 issuerPublicCryptoKeyBytes:", issuerPublicCryptoKeyBytes);

      // Verifica disponibilità chiave privata del client
      console.log("Tipo encryptedMessageBytes:", Object.prototype.toString.call(encryptedMessageBytes));
      console.log("Tipo nonce:", Object.prototype.toString.call(nonce));
      console.log("Tipo issuerPublicCryptoKeyBytes:", Object.prototype.toString.call(issuerPublicCryptoKeyBytes));
      console.log("Tipo clientPrivateCryptoKey:", Object.prototype.toString.call(clientPrivateCryptoKey));

      console.log("encryptedMessageBytes instanceof Uint8Array?", encryptedMessageBytes instanceof Uint8Array);
      console.log("nonce instanceof Uint8Array?", nonce instanceof Uint8Array);
      console.log("issuerPublicCryptoKeyBytes instanceof Uint8Array?", issuerPublicCryptoKeyBytes instanceof Uint8Array);
      console.log("clientPrivateCryptoKey instanceof Uint8Array?", clientPrivateCryptoKeyBytes instanceof Uint8Array);


      if (!clientPrivateCryptoKeyBytes) {
        throw new Error("Chiave privata del client mancante.");
      }
      console.log("🔑 Chiave privata client:", clientPrivateCryptoKey);

      // 🔓 Decrittazione
     

     
      const decryptedBytes = nacl.box.open(
        encryptedMessageBytes,
        nonce,
        issuerPublicCryptoKeyBytes,
        clientPrivateCryptoKeyBytes
      );

      if (!decryptedBytes) {
        throw new Error("Decrittazione fallita!");
      }

      // Parsing
      const decryptedVCJson = naclUtil.encodeUTF8(decryptedBytes);
      console.log("📜 VC decrittata raw JSON string:", decryptedVCJson);

      const decryptedVC = JSON.parse(decryptedVCJson);

      console.log("✅ VC decrittata (parsed):", JSON.stringify(decryptedVC, null, 2));

      // 🔹 Salva in array globale
      if (!global.vcStorage) global.vcStorage = [];
      global.vcStorage.push(decryptedVC);

      console.log("📦 VC salvata in memoria. Totali:", global.vcStorage.length);

      res.json({ message: "✅ VC decrittata e salvata in array!" });

      // Menu
      setTimeout(() => {
        console.log("📜 CLIENT - Avvio del menu...");
        clientMenu();
      }, 100);

    } catch (decodeError) {
      console.error("❌ Errore durante la decodifica Base64 o decrittazione:", decodeError);
      res.status(500).json({ error: "❌ Errore durante la decodifica o decrittazione." });
    }

  } catch (error) {
    console.error("❌ Errore nella gestione della richiesta:", error.message);
    res.status(500).json({ error: "❌ Errore interno nel server." });
  }
}


async function createClientIdentity(controller) {
  
  const keys = generateClientKeys();try {
    console.log("🚀 Generazione dell'identità del client...");

    // 🔑 Genera le chiavi di firma e crittografia
    

    // 🔹 Inizializza il resolver
    const resolver = new Resolver({ ...getDidKeyResolver() });

    // 🔹 Crea un agente DID con le chiavi generate
    agent = createAgent({
      plugins: [
        new KeyManager({
          store: new MemoryKeyStore(),
          kms: { local: new KeyManagementSystem(new MemoryPrivateKeyStore()) },
        }),
        new DIDManager({
          store: new MemoryDIDStore(),
          defaultProvider: 'did:key',
          providers: { 'did:key': new KeyDIDProvider({ defaultKms: 'local' }) },
        }),
        new DIDResolverPlugin({ resolver }),
      ],
    });

    // 🔹 Crea un DID associando le chiavi generate
    identity = await agent.didManagerCreate({
      did: 'did:key',
      keys: [
        {
          type: 'Ed25519',
          publicKeyHex: keys.signingKeys.publicKey,
          privateKeyHex: keys.signingKeys.privateKey,
          kms: 'local'
        },
        {
          type: 'X25519',
          publicKeyHex: keys.encryptionKeys.publicKey,
          privateKeyHex: keys.encryptionKeys.privateKey,
          kms: 'local'
        }
      ]
    });

    console.log("✅ DID generato correttamente:", identity.did);
  } catch (error) {
    console.error("❌ Errore durante la creazione del DID:", error.message);
  }
  console.log("did document",identity.didDocument);
  clientPrivateCryptoKey= keys.encryptionKeys.publicKey;
  clientPublicCryptoKey=keys.encryptionKeys.privateKey;
  clientPublicSignKey =keys.signingKeys.publicKey;
  clientPrivateSignKey=keys.signingKeys.privateKey;
  saveKeys(controller);
}


async function getPublicKeyByDID(did) {
  try {
    console.log(`🔍 Richiesta chiave pubblica per DID: ${did}`);
    const response = await axios.get(`${resolverURL}/resolve/${did}`);

    if (response.data && response.data.publicKey) {
      console.log("✅ Chiave pubblica ricevuta con successo!");
      return response.data.publicKey;
    } else {
      console.log("❌ Nessuna chiave pubblica trovata per questo DID.");
      return null;
    }
  } catch (error) {
    console.error("❌ Errore nella richiesta al resolver:", error.message);
    return null;
  }
}

async function encryptAndSendMessage(did, vc, enteDid) {
  let didDocument = await agent.resolveDid({ didUrl: did });
  enteCryptoPublicKey = await getPublicKeyByDID(enteDid); // ✅ Usa await per risolvere il Promise
  const entePublicKeyBytes = Buffer.from(enteCryptoPublicKey, 'base64'); // ✅ Converti da Base64


  try {
        const signingKeyPair = {
        publicKey: Buffer.from(clientPublicSignKey, 'hex'),
        secretKey: Buffer.from(clientPrivateSignKey, 'hex'),
      };

      const encryptionKeyPair = {
        publicKey: Buffer.from(clientPublicCryptoKey, 'hex'),
        secretKey: Buffer.from(clientPrivateCryptoKey, 'hex'),
      };
      let didDocument = await agent.resolveDid({ didUrl: did });

      const publicKeyEntry = {
      id: `${didDocument.didDocument.id}#key-1`,
      type: "Ed25519VerificationKey2018",
      controller: didDocument.didDocument.id,
      publicKeyHex: signingKeyPair.publicKey, // ✅ Usa la chiave di firma già generata
    };

    const encryptionKeyEntry = {
      id: `${didDocument.didDocument.id}#key-encryption`,
      type: "X25519KeyAgreementKey2019",
      controller: didDocument.didDocument.id,
      publicKeyHex: encryptionKeyPair.publicKey, // ✅ Usa la chiave di crittografia già generata
    };
    

    // 🔹 Aggiungiamo le chiavi nel DID Document
    didDocument.didDocument.verificationMethod = [...(didDocument.didDocument.verificationMethod || []), publicKeyEntry];
    didDocument.didDocument.keyAgreement = [...(didDocument.didDocument.keyAgreement || []), encryptionKeyEntry];

    
    


    const message = JSON.stringify({ vc }); 
    const messageBytes = naclUtil.decodeUTF8(message);
    console.log("Messaggio decodificato utf8: ",messageBytes);
    const signatureBytes = nacl.sign.detached(messageBytes, signingKeyPair.secretKey); // ✅ Usa la chiave privata del client
    const signatureBase64 = naclUtil.encodeBase64(signatureBytes);
    const nonce = nacl.randomBytes(nacl.box.nonceLength); // ✅ Genera un nonce sicuro
    
    console.log("🔎 CLIENT - Nonce usato per criptare (HEX):", Buffer.from(nonce).toString('hex'));


    const encryptedMessageBytes = nacl.box(
    messageBytes,
    nonce,
    entePublicKeyBytes, // ✅ Chiave pubblica dell'ente
    encryptionKeyPair.secretKey // 🔐 Chiave privata del client
  );

    const encryptedMessage = {
      nonce: naclUtil.encodeBase64(nonce), 
      ciphertext: naclUtil.encodeBase64(encryptedMessageBytes)
    };
    console.log("🔎 CLIENT - Chiave pubblica nel formato DID Document:", Array.from(Buffer.from(encryptionKeyPair.publicKey)));


    
    console.log("🔎 CLIENT - Nonce (Hex):", Buffer.from(encryptedMessage.nonce).toString('hex'));
    console.log("🔎 CLIENT - Ciphertext (Base64):", encryptedMessage.ciphertext.toString('base64'));

    

    
    

    
     const response = await axios.post(`${enteURL}/receive-message`, {
  encryptedMessage,
  signature: signatureBase64,
  senderDID: identity.did,
  didDocument,
  clientPort: getPorts().clientPort // 🔹 Aggiunge la porta del client
});




    // 🔎 Controlla la risposta prima di usarla
    console.log("✅ CLIENT - Risposta ricevuta dal server:", response.data);
    return response.data; // 🔥 Ora restituisci `response.data` alla funzione chiamante
    } catch (error) {
    console.error("❌ Errore nell'invio del messaggio:", error.message);
    console.error("🔎 SERVER - Stack completo dell'errore:", error.stack);
  }
}


export async function showMenu() {
  let controller; // ✅ Dichiarazione globale per mantenere il valore 

  if (!identity) {
    console.log("❌ Nessuna identità trovata");
    controller = await askController(); // ✅ Ora controller viene memorizzato correttamente
    await createClientIdentity(controller);
  }

  if (!controller) {
    console.log("⚠️ Errore: Controller non definito!");
    return;
  }

  // 🔎 Assegna le chiavi alle variabili globali con `controller`
  clientPrivateCryptoKey = fs.readFileSync(`${keysPath}/${controller}_x25519_private_crypto.txt`, 'utf8');
  clientPublicCryptoKey = fs.readFileSync(`${keysPath}/${controller}_x25519_public_crypto.txt`, 'utf8');
  clientPrivateSignKey = fs.readFileSync(`${keysPath}/${controller}_ed25519_private_sign.txt`, 'utf8');
  clientPublicSignKey = fs.readFileSync(`${keysPath}/${controller}_ed25519_public_sign.txt`, 'utf8');

  console.log("\n👤 DID attuale del client:", identity.did);
  clientMenu();
}

function clientMenu() {
  console.log("\n👤 DID attuale del client:", identity.did);
  rl.question(
    '\n🔸 Menu Client\n1️⃣ Invia DID e VC cifrati all\'ente\n2️⃣ Recupera chiave pubblica ente\n3️⃣ Registra DID nel resolver\n4️⃣ Visualizza richieste accettate ',
    async (choice) => {
      await handleChoice(choice);
    }
  );
}

async function askController() {
  return new Promise((resolve) => {
    rl.question("📝 Inserisci il tuo controller: ", (controller) => {
      return resolve(controller); // ✅ Ora il valore viene restituito direttamente
    });
  });
}

async function handleChoice(choice) {
  switch (choice) {
    case '1':
      rl.question('🔹 Inserisci DID ente: ', async (enteDid) => {
        rl.question('💳 Inserisci Verifiable Credential (VC): ', async (vc) => {
          console.log("👤 DID del client usato:", identity.did);
          await encryptAndSendMessage(identity.did, vc, enteDid);
          
          clientMenu();
        });
      });
      break;
    case '2':
      rl.question('🔹 Inserisci DID ente: ', async (enteDid) => {
        await getPublicKeyByDID(enteDid);
        clientMenu();
      });
      break;
    case '3':
      console.log("⚠️ Funzione di registrazione DID da implementare");
      clientMenu();
      break;
    case '4':
       console.log("📜 Visualizzazione delle VC accettate...");
        await viewAcceptedVCs();
        clientMenu(); // 🔹 Torna al menu dopo la visualizzazione
        break;
    default:
      console.log("❌ Scelta non valida.");
      clientMenu();
  }
}
/*askServerPort().then((serverPort) => {
  setServerPort(serverPort);

  findAvailablePort().then((clientPort) => {
    setClientPort(clientPort);

    app.listen(clientPort, () => {
      console.log(`🚀 Client in ascolto su porta ${clientPort}`);
      console.log(`🔎 Server rilevato su porta ${serverPort}`);
      
      const { serverPort, clientPort } = getPorts();
      enteUrl = `http://localhost:${getPorts().serverPort}`;

      console.log(`🔹 Accesso globale alle porte → Server: ${serverPort}, Client: ${clientPort}`);

      showMenu();
    });
  });
});*/ 
showMenu();



// Avvio del menu
