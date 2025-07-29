import readline from 'readline';
import net from 'net';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createAgent } from '@veramo/core';
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager';
import { KeyManagementSystem } from '@veramo/kms-local';
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager';
import { KeyDIDProvider, getDidKeyResolver } from '@veramo/did-provider-key';
import { DIDResolverPlugin } from '@veramo/did-resolver';
import { Resolver } from 'did-resolver';
import axios from 'axios';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
import { getResolver } from 'peer-did-resolver';
import { PeerDIDProvider } from '@veramo/did-provider-peer'
import { exec } from 'child_process';


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class ClientSetup {
  constructor(rl) {
    this.serverPort = null;
    this.clientPort = null;
    this.controller = null;
    this.identity = null;
    this.clientPrivateCryptoKey = null;
    this.clientPublicCryptoKey = null;
    this.clientPrivateSignKey = null;
    this.clientPublicSignKey = null;
    this.clientFilesPath=null;
    this.registrationResponses=[];
    this.vcStorage = []; // 🔹 Nuovo array per memorizzare le VC ricevute
    this.rl = rl;
    this.verifierRequests = []; // array per richieste da verifier
    this.authorizedPresentations = [];

  }
  createClientFilesFolder(controller) {
  const sanitizedController = controller.replace(/[^a-zA-Z0-9_-]/g, "_");

  const baseFolder = path.join(__dirname, "ClientFiles");
  const folderPath = path.join(baseFolder, sanitizedController);

  if (!fs.existsSync(folderPath)) {
    fs.mkdirSync(folderPath, { recursive: true });
    console.log(`📁 Cartella Client creata: ${folderPath}`);
  } else {
    console.log(`ℹ️ Cartella Client già esistente: ${folderPath}`);
  }

  return folderPath;
}



  async initialize() {
    this.serverPort = await this.askServerPort();
    this.clientPort = await this.findAvailableClientPort();


    console.log(`✅ Server port: ${this.serverPort}`);
    console.log(`✅ Client port: ${this.clientPort}`);

    await this.showMenu();
  }
  async changeServerPort()
  {
    this.serverPort = await this.askServerPort();
    console.log("Porta del server cambiata, la nuova è: ",this.serverPort);
  }
  async showMenu() {
    if (!this.identity) {
      console.log("❌ Nessuna identità trovata");
      this.controller = await this.askController();
      this.identity = await this.createClientIdentity(this.controller); // ✅ ora viene assegnata
    }

    if (!this.controller) {
      console.log("⚠️ Errore: Controller non definito!");
      return;
    }

    console.log("📜 Avvio del menu...");
  }

  askServerPort() {
    return new Promise((resolve) => {
      this.rl.question("🔹 Inserisci la porta del server: ", (serverPort) => {
        resolve(serverPort);
      });
    });
  }

  askController() {
    let controller=null;
    return new Promise((resolve) => {
      
      this.rl.question("🔹 Inserisci il controller: ", (controller) => {
        this.controller=controller;
        resolve(controller);
      });
    });
    
  }
async getPendingVerifierRequests() {
  if(!Array.isArray(this.verifierRequests)){
    console.log("questo non è un array, ri inizializziamo");
    this.verifierRequests=[];
  }
  return this.verifierRequests;
}

askUser(rl, question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer.trim());
    });
  });
}
findAvailableClientPort(startPort = 5000) {
  return new Promise((resolve) => {
    console.log(`🔎 Tentativo di avvio su porta: ${startPort}...`);

    const server = net.createServer();
    server.listen(startPort, () => {
      console.log(`✅ Porta disponibile trovata: ${startPort}`);
      console.log(`🟢 Client in ascolto sulla porta ${startPort}...`);
      server.close(() => resolve(startPort));
    });

    server.on("error", () => {
      console.log(`❌ Porta ${startPort} occupata, provo la successiva...`);
      resolve(this.findAvailableClientPort(startPort + 1));
    });
  });
}


async createClientIdentity(controller) {
  const keys = await this.generateClientKeys();
  let identity;

  try {
    console.log("🚀 Generazione dell'identità del client con did:key...");

    const resolver = new Resolver({
      ...getDidKeyResolver(),
    });

    const agent = createAgent({
      plugins: [
        new KeyManager({
          store: new MemoryKeyStore(),
          kms: { local: new KeyManagementSystem(new MemoryPrivateKeyStore()) },
        }),
        new DIDManager({
          store: new MemoryDIDStore(),
          defaultProvider: 'did:key',
          providers: {
            'did:key': new KeyDIDProvider({ defaultKms: 'local' }),
          },
        }),
        new DIDResolverPlugin({ resolver }),
      ],
    });

    identity = await agent.didManagerCreate({
      provider: 'did:key',
      keys: [
        {
          type: 'Ed25519',
          publicKeyHex: keys.signingKeys.publicKey,
          privateKeyHex: keys.signingKeys.privateKey,
          kms: 'local',
        },
        {
          type: 'X25519',
          publicKeyHex: keys.encryptionKeys.publicKey,
          privateKeyHex: keys.encryptionKeys.privateKey,
          kms: 'local',
        },
      ],
    });

    console.log("✅ DID generato correttamente:", identity.did);

    // 🔍 Risolvi DID esistente
    const didResolution = await agent.resolveDid({ didUrl: identity.did });
    const didDoc = { ...didResolution.didDocument };

    // 🧠 Override selettivo
    didDoc.verificationMethod = [
      {
        id: `${identity.did}#key-1`,
        type: 'Ed25519VerificationKey2018',
        controller: identity.did,
        publicKeyHex: keys.signingKeys.publicKey,
      },
    ];

    didDoc.keyAgreement = [
      {
        id: `${identity.did}#key-x25519-1`,
        type: 'X25519KeyAgreementKey2019',
        controller: identity.did,
        publicKeyHex: keys.encryptionKeys.publicKey,
      },
    ];

    didDoc.service = [
      {
        id: `${identity.did}#msg`,
        type: 'DIDCommMessaging',
        serviceEndpoint: 'http://localhost:5000/msg',
      },
    ];

    identity.didDocument = didDoc;

    // 📝 Assegna chiavi alla classe
    this.identity = identity;
    this.clientPrivateSignKey = keys.signingKeys.privateKey;
    this.clientPublicSignKey = keys.signingKeys.publicKey;
    this.clientPrivateCryptoKey = keys.encryptionKeys.privateKey;
    this.clientPublicCryptoKey = keys.encryptionKeys.publicKey;

    // 📄 Log del documento finale
    console.log("📄 Documento DID (override parziale):");
    console.log(JSON.stringify(identity.didDocument, null, 2));

    return identity;
  } catch (error) {
    console.error("❌ Errore durante la creazione del DID:", error.message);
    return null;
  }
}





  async generateClientKeys() {
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
  const keyBytes = new Uint8Array(Buffer.from(publicEncryptionKey, 'hex'));
  console.log(`🔐 clientPublicCryptoKeyBytes: Uint8Array(${keyBytes.length}) [ ${Array.from(keyBytes).join(', ')} ]`);
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

  getKeys() {
    return {
      publicCryptoKey: this.clientPublicCryptoKey,
      privateCryptoKey: this.clientPrivateCryptoKey,
      publicSignKey: this.clientPublicSignKey,
      privateSignKey: this.clientPrivateSignKey,
    };
  }

  getDidDocument() {
    return this.identity ? this.identity : null;
  }

  getPorts() {
    return {
      serverPort: this.serverPort,
      clientPort: this.clientPort,
    };
  }


async  viewAcceptedVCs(rl) {
  if (!this.vcStorage || this.vcStorage.length === 0) {
    console.log("✅ Nessuna VC ricevuta.");
    return;
  }

  console.log("\n📜 LISTA DELLE VC ACCETTATE:");
  this.vcStorage.forEach((vc, index) => {
    const full = vc.full || {};
    const subject = full.credentialSubject || {};
    const evidence = full.evidence || [];
    const firmaOK = vc.signatureVerified || (vc.verification?.success === true);

    console.log(`\n🔢 VC #${index + 1}`);
    console.log(`🪪 DID Issuer: ${full.issuer || "N/D"}`);
    console.log(`🧾 Intestatario: ${subject.id || "N/D"}`);
    console.log(`🗓️  Data emissione: ${full.issuanceDate || "N/D"}`);
    console.log(`📄 Messaggio: ${subject.message || "N/D"}`);
    console.log(`📁 Tipo documento: ${subject.documentType || "N/D"}`);
    console.log(`📎 Allegati: ${evidence.map(e => e.fileName || "??").join(', ') || "Nessuno"}`);
    console.log(`🔐 Firma: ${firmaOK ? "✅ Verificata" : "❌ Non valida o non presente"}`);
    console.log("────────────────────────────");
  });

  const scelta = await new Promise(resolve =>
    rl.question("\n📂 Inserisci il numero della VC per aprire un file (0 per annullare): ", resolve)
  );

  const idx = parseInt(scelta, 10) - 1;
  if (idx < 0 || idx >= this.vcStorage.length) {
    console.log("❎ Nessuna VC selezionata.");
    return;
  }

  const vc = this.vcStorage[idx];
  const pathFolder = vc.pathFolder;
  const files = (vc.full?.evidence || []).map(e => e.fileName).filter(Boolean);

  if (!pathFolder || files.length === 0) {
    console.log("⚠️ Nessun allegato disponibile per questa VC.");
    return;
  }

  console.log("\n📎 Allegati disponibili:");
  files.forEach((fileName, i) => {
    console.log(`${i + 1}. ${fileName}`);
  });

  const sceltaFile = await new Promise(resolve =>
    rl.question("📄 Inserisci il numero del file da aprire: ", resolve)
  );

  const fileIdx = parseInt(sceltaFile, 10) - 1;
  if (fileIdx < 0 || fileIdx >= files.length) {
    console.log("❎ Nessun file aperto.");
    return;
  }

  const fullPath = path.join(pathFolder, files[fileIdx]);

  // Apri file (Linux/macOS – per Windows usa 'start')
  exec(`xdg-open "${fullPath}"`, err => {
    if (err) {
      console.error("❌ Errore nell'apertura del file:", err.message);
    } else {
      console.log("📄 File aperto con successo!");
    }
  });
}



    async viewAcceptedRegistrationRequest() {
    if (!this.registrationResponses || this.registrationResponses.length === 0) {
      console.log("✅ Nessuna VC ricevuta.");
      return;
    }

    console.log("📜 Richiesta di registrazione:");
    this.vcStorage.forEach((vc, index) => {
      console.log(`🔢 ${index + 1} - DID Issuer: ${vc.issuer || "N/D"}`);
      console.log(`📜 Contenuto VC: ${JSON.stringify(vc, null, 2)}`);
      console.log("────────────────────────────");
    });
  }
  
async handleVerifierRequests() {
  // 1. Verifica richieste disponibili
  if (!this.verifierRequests) {
    throw new Error(`❌ verifierRequests non è definito.`);
  }

  if (this.verifierRequests.length === 0) {
    console.log("✅ Nessuna richiesta da parte di Verifier al momento.");
    return;
  }

  // 2. Mostra elenco richieste
  console.log("\n📬 Richieste da Verifier:");
  this.verifierRequests.forEach((req, i) => {
    const payload = req.payload || {};
    console.log(`${i + 1}. Da: ${payload.verifierDID} | Tipo richiesto: ${payload.requestedType} | Porta: ${payload.verifierPort}`);
  });

  const choice = await askUser(this.rl, "\n➡️ Seleziona la richiesta da gestire (0 per annullare): ");
  const selectedIndex = parseInt(choice, 10) - 1;

  if (choice === '0' || selectedIndex < 0 || selectedIndex >= this.verifierRequests.length) {
    console.log("❎ Operazione annullata.");
    return;
  }

  // 3. Mostra dettagli della richiesta selezionata
  const selectedRequest = this.verifierRequests[selectedIndex];
  const payload = selectedRequest.payload;

  console.log(`\n📋 Dettagli richiesta #${selectedIndex + 1}:`);
  console.log(`🔹 Verifier DID: ${payload.verifierDID}`);
  console.log(`📄 Tipo richiesto: ${payload.requestedType}`);
  console.log(`🏷️  Scopo: ${payload.purpose}`);
  console.log(`🌐 Dominio: ${payload.domain}`);
  console.log(`📍 Porta: ${payload.verifierPort}`);
  console.log(`⏰ Timestamp: ${payload.timestamp}`);
  console.log(`🔐 Challenge: ${payload.challenge}`);

  const confirm = await askUser(this.rl, "\n✅ Vuoi procedere con questa richiesta? (y/n): ");
  if (confirm.toLowerCase() !== 'y') {
    console.log("⏹️ Richiesta ignorata.");
    return { accepted: false };
  }

  // 4. Filtra VC compatibili
  const matchingVCs = this.vcStorage.filter(vc => {
    const tipo = vc.full?.credentialSubject?.documentType || vc.full?.type?.[1];
    return tipo === payload.requestedType;
  });

  if (matchingVCs.length === 0) {
    console.log(`🚫 Nessuna VC disponibile del tipo '${payload.requestedType}'.`);
    return { accepted: false };
  }

  // 5. Se più VC, lascia scegliere quale inviare
  let selectedVC;
  if (matchingVCs.length === 1) {
    selectedVC = matchingVCs[0];
    console.log("✅ VC corrispondente trovata automaticamente.");
  } else {
    console.log("\n🎯 VC disponibili per il tipo richiesto:");
    matchingVCs.forEach((vc, i) => {
      const subject = vc.full.credentialSubject;
      console.log(`${i + 1}. Intestatario: ${subject.id} | Documento: ${subject.documentType} | Allegati: ${subject.fileCount}`);
    });

    const sceltaVC = await askUser(this.rl, "📄 Seleziona la VC da inviare (numero): ");
    const idx = parseInt(sceltaVC, 10) - 1;

    if (idx < 0 || idx >= matchingVCs.length) {
      console.log("❎ Nessuna VC selezionata.");
      return { accepted: false };
    }

    selectedVC = matchingVCs[idx];
  }

  // 6. Ritorna tutto il necessario per inviare la VP
  return {
    accepted: true,
    selectedRequest,
    selectedVC,
    index: selectedIndex,
    verifierDID: payload.verifierDID,
    requestedType: payload.requestedType
  };
}

async sendVPtoVerifier(verifierPort, vp, verifierPublicCryptoKeyBase64, clientPrivateCryptoKeyBase64) {
  try {
    const url = `http://localhost:${verifierPort}/vp-response`;

    // Converti chiavi da base64 a Uint8Array
    const verifierPublicKey = Uint8Array.from(Buffer.from(verifierPublicCryptoKeyBase64, 'base64'));
    const clientPrivateKey = Uint8Array.from(Buffer.from(clientPrivateCryptoKeyBase64, 'base64'));

    // Ricava la chiave pubblica del client (se non già salvata altrove)
    const clientKeyPair = nacl.box.keyPair.fromSecretKey(clientPrivateKey);
    const clientPublicKey = clientKeyPair.publicKey;

    // Serializza la VP
    const messageUint8 = naclUtil.decodeUTF8(JSON.stringify(vp));

    // Genera nonce casuale
    const nonce = nacl.randomBytes(nacl.box.nonceLength);

    // Cripta la VP
    const encrypted = nacl.box(
      messageUint8,
      nonce,
      verifierPublicKey,
      clientPrivateKey
    );

    // Prepara payload
    const payload = {
      encryptedVP: naclUtil.encodeBase64(encrypted),
      nonce: naclUtil.encodeBase64(nonce),
      senderPublicKey: naclUtil.encodeBase64(clientPublicKey)
    };

    console.log(`📤 Invio VP cifrata al verifier (porta ${verifierPort})...`);

    // POST al verifier
    const response = await axios.post(url, payload);
    console.log("✅ Risposta del verifier:", response.data);
  } catch (error) {
    console.error("❌ Errore durante l'invio della VP:", error.message);
    throw error;
  }
}
}
async function askUser(rl, question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer.trim());
    });
  });
}
 

