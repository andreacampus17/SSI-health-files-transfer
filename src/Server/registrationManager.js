import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
import axios from 'axios';
import {v4 as uuidv4} from 'uuid'
import { createHash } from 'crypto';
import canonicalize from 'canonicalize';
import path from 'path';
import fs from 'fs'; // Per fs.createReadStream(...)
import FormData from 'form-data';
import crypto from 'crypto';
import { exec } from 'child_process'
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


export class RegistrationManager {
  constructor(rl,serverSetup) {
    this.rl = rl; // 🔹 Salviamo l'istanza di readline passata da ServerManager
    this.registrationRequests = [];
    this.acceptedRequests = [];
    this.globalClientDidDocument = null;
    this.serverSetup = serverSetup; // 🔹 Collegamento al setup del server
    this.verifier_accepted_requests=[];
    this.revokeRequests=[];
    this.challenges=[];
    this.pendingVCRequests=[];
}
  askUser(rl, question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer.trim());
    });
  });
}
/*encryptedMessage,
        signature: Buffer.from(clientSignature).toString('hex'),
        senderDID: didClient,
        didDocument
      });*/ 
  receiveRegistrationRequest({ encryptedMessage, signature, senderDID, didDocument, clientPort,clientUs }) {
    if (!encryptedMessage || !senderDID || !signature || !didDocument|| !clientPort || !clientUs) {
      console.error("❌ Dati mancanti nella richiesta!");
      return false;
    }
    console.log("📦 clientUs dentro la richiesta accettata:", clientUs);

    this.registrationRequests.push({
      senderDID,
      didDocument,
      encryptedMessage,
      signature,
      timestamp: new Date().toISOString(),
      clientPort,
      clientUs
    });

    //console.log(`✅ Registrazione ricevuta da: ${JSON.stringify(senderDID)}`);
    

    //console.log("📦 Registrazione salvata:", this.registrationRequests[this.registrationRequests.length - 1]);

    return true;
  }

  decryptMessage(request, entePrivateCryptoKeyBytes) {
    try {
      const nonce = Buffer.from(request.encryptedMessage.nonce, "base64");
      const ciphertext = Buffer.from(request.encryptedMessage.ciphertext, "base64");
      const keyAgreementEntry = request.didDocument?.didDocument?.keyAgreement?.find(entry => entry.id?.includes("key-encryption"));

      if (!keyAgreementEntry?.publicKeyHex?.data) {
        throw new Error("❌ Chiave pubblica del client non trovata!");
      }

      const clientPublicCryptoKeyBytes = Uint8Array.from(keyAgreementEntry.publicKeyHex.data);
      const decryptedMessageBytes = nacl.box.open(ciphertext, nonce, clientPublicCryptoKeyBytes, entePrivateCryptoKeyBytes);

      if (!decryptedMessageBytes) {
        throw new Error("❌ Errore nella decriptazione!");
      }

      return naclUtil.encodeUTF8(decryptedMessageBytes);
    } catch (error) {
      console.error("❌ Errore durante la decriptazione:", error.message);
      return null;
    }
  }
  async generateChallenge()
  {
    return uuidv4;
  }
  async verifierRequest(serverSp) {
  try {
    const fiscalCode = await new Promise(resolve => {
      this.rl.question("Inserisci il codice fiscale del client target: ", answer => {
        resolve(answer.trim());
      });
    });

    try {
      const resolverResponse = await axios.post('http://localhost:4000/verifier-resolve-request', {
        fiscalCode
      });
      const clientInfo = resolverResponse.data;
      //console.log("✅ Info client recuperate:", clientInfo);

      //console.log("🔎 Info client recuperate dal resolver:", clientInfo);
    } catch (err) {
      console.error("❌ Impossibile ottenere le informazioni del client dal resolver:", err.response?.data || err.message);
      return;
    }

    // Chiedi la porta del client con readline
    const clientPort = await new Promise(resolve => {
      this.rl.question("Inserisci la porta del client a cui inviare la richiesta VP: ", answer => {
        resolve(answer.trim());
      });
    });
    const requestedT= await new Promise(resolve=>{
      this.rl.question("Quale tipo di credenziale vuoi richiedere?",answer => {
        resolve(answer.trim());
      });
    });

    if (!clientPort || isNaN(clientPort)) {
      console.log("Porta client non valida. Operazione annullata.");
      return;
    }

    // Costruisci la richiesta
    const vpRequest = {
      verifierDID: serverSp.issuerDid,
      requestedType: requestedT,
      verifierPort: serverSp.serverPort,
      challenge:this.generateChallenge(),
      domain:"heltcare.example.it",
      purpose:"Accesso al fascicolo sanitario elettronico",
      timestamp: new Date().toISOString()
    };
    const encodedPayload =naclUtil.decodeUTF8(JSON.stringify(vpRequest));

    const signature = nacl.sign.detached(encodedPayload,Uint8Array.from(Buffer.from(serverSp.entePrivateSignKey, "base64")));
    const signedRequest ={
      payload: vpRequest,
      proof: {
        type:"ED2519Signature2020",
        created: new Date().toString(),
        verificationMethod: `${serverSp.issuerDid}#key-1`,
        signatureValue: naclUtil.encodeBase64(signature)
        }
    }

    const clientUrl = `http://localhost:${clientPort}/verifier-request`;

    //console.log(`Invio richiesta VP al client sulla porta ${clientPort}:`, vpRequest);

    const response = await axios.post(clientUrl, signedRequest);

    //console.log("Risposta del client:", response.data);
    return true;

  } catch (error) {
    console.error("Errore nell'invio della richiesta VP al client:", error.message)
    return false;

  }
}


  verifySignature(decryptedMessage, signature, didDocument) {
    try {
      const verificationMethod = didDocument.didDocument.verificationMethod.find(
        method => method.type === "Ed25519VerificationKey2018" && method.publicKeyHex?.data
      );

      if (!verificationMethod) {
        throw new Error("❌ Nessuna chiave pubblica di firma trovata!");
      }

      const publicKeySignBytes = Uint8Array.from(verificationMethod.publicKeyHex.data);
      const signatureBytes = Buffer.from(signature, "base64");
      const messageBytes = naclUtil.decodeUTF8(decryptedMessage);

      return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeySignBytes);
    } catch (error) {
      console.error("❌ Errore nella verifica della firma:", error.message);
      return false;
    }
  }

async acceptOrRejectRequest(number, action, enteKeys) {
  if (number < 1 || number > this.registrationRequests.length) {
    const msg = "❌ Numero richiesta non valido!";
    console.error(msg);
    return { status: 'invalid_request_number', message: msg };
  }

  const request = this.registrationRequests[number - 1];

  if (action === "accept") {
    this.acceptedRequests.push(request);

    const clientDidDoc = request.didDocument;
    const clientCryptoKeyBytes = await this.extractKeyAgreementKeyBytes(clientDidDoc, "X25519");
    const clientSignKeyBytes = await this.extractPublicKeyBytes(clientDidDoc, "Ed25519");

    const signingPublicKeyBase64 = Buffer.from(clientSignKeyBytes).toString('base64');
    const encryptionPublicKeyBase64 = Buffer.from(clientCryptoKeyBytes).toString('base64');

    const result = await this.registerClientOnResolver(
      request.senderDID,
      request.codice_fiscale,
      signingPublicKeyBase64,
      encryptionPublicKeyBase64
    );

    switch (result.status) {
      case 'ok':
        console.log(`✅ Client ${request.codice_fiscale} registrato correttamente.`);
        break;
      case 'duplicate':
        console.warn(`⚠️ Il codice fiscale ${request.codice_fiscale} è già presente nel resolver.`);
        break;
      case 'error':
      case 'network_error':
        console.error(`❌ Problema durante la registrazione: ${result.message}`);
        break;
      default:
        console.warn(`⚠️ Risposta inattesa:`, result);
        break;
    }

    console.log(`✅ Richiesta ${number} accettata!`);
    await this.processRegistrationRequest(request, enteKeys);

    this.registrationRequests.splice(number - 1, 1);
    return {
      status: result.status,
      message: `Richiesta accettata. Stato registrazione: ${result.status}`,
      codiceFiscale: request.codice_fiscale
    };
  } else {
    console.log(`❌ Richiesta ${number} rifiutata!`);
    this.registrationRequests.splice(number - 1, 1);
    return {
      status: 'rejected',
      message: `Richiesta ${number} rifiutata.`,
      codiceFiscale: request.codice_fiscale
    };
  }
}


async processRegistrationRequest(request, enteKeys) {
  try {
    const formattedDID = typeof request.senderDID === "object" 
      ? JSON.stringify(request.senderDID, null, 2) 
      : request.senderDID;

    const formattedDidDocument = typeof request.didDocument === "object" 
      ? JSON.stringify(request.didDocument, null, 2) 
      : request.didDocument;

    //console.log(`✅ Registrazione ricevuta da: ${formattedDID}`);
    //console.log("📄 DID Document:", formattedDidDocument);

    const credentialType = request.credentialType || "RegistrazioneGenerica";

    // 🎫 Costruzione VC
    const vcPayload = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential", credentialType],
      issuer: enteKeys.issuerDid,
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: request.senderDID,
        message: "✅ Registrazione accettata!"
      }
    };

    // 🔐 Chiavi crittografiche
    const clientPublicCryptoKeyBytes = await this.extractKeyAgreementKeyBytes(request.didDocument, "X25519");
    const entePrivateCryptoKeyBytes = Buffer.from(enteKeys.privateCryptoKey, "base64");

    // 📝 Canonicalizzazione e firma
    const canonicalVC = canonicalize(vcPayload);
    const vcBytes = new TextEncoder().encode(canonicalVC);
    const signature = nacl.sign.detached(vcBytes, Buffer.from(enteKeys.privateSignKey, "base64"));

    // 🧾 VC firmata (proof include canonical payload)
    const signedVC = {
      ...vcPayload,
      proof: {
        type: "Ed25519Signature2018",
        created: new Date().toISOString(),
        proofPurpose: "assertionMethod",
        verificationMethod: `${enteKeys.issuerDid}#key-1`,
        signatureValue: Buffer.from(signature).toString('base64'),
        canonicalPayload: canonicalVC
      }
    };

    // 🔒 Crittografia
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const signedVCBytes = new TextEncoder().encode(JSON.stringify(signedVC));

    const encryptedMessageBytes = nacl.box(
      signedVCBytes,
      nonce,
      clientPublicCryptoKeyBytes,
      entePrivateCryptoKeyBytes
    );

    const encryptedResponse = {
      nonce: naclUtil.encodeBase64(nonce),
      ciphertext: naclUtil.encodeBase64(encryptedMessageBytes),
      issuerPublicCryptoKey: this.serverSetup.entePublicCryptoKey,
      issuerPublicSignKey: enteKeys.publicSignKey
    };

    //console.log("🚀 Invio al client sulla porta:", request.clientPort);
    //console.log("📦 Payload VC in uscita:");
    //console.log(JSON.stringify(encryptedResponse, null, 2));

    const clientURL = `http://localhost:${request.clientPort}`;
    await axios.post(`${clientURL}/receive-server-vc`, encryptedResponse);

    console.log("✅ VC inviata al client!");
    return { status: "success" };

  } catch (error) {
    console.error("❌ Errore nell'elaborazione della richiesta:", error.message);
  }
}
async processRegistrationRequest(request, enteKeys) {
  try {
    const formattedDID = typeof request.senderDID === "object" 
      ? JSON.stringify(request.senderDID, null, 2) 
      : request.senderDID;

    const formattedDidDocument = typeof request.didDocument === "object" 
      ? JSON.stringify(request.didDocument, null, 2) 
      : request.didDocument;

    //console.log(`✅ Registrazione ricevuta da: ${formattedDID}`);
    //console.log("📄 DID Document:", formattedDidDocument);

    const credentialType = request.credentialType || "RegistrazioneGenerica";

    // 🎫 Costruzione VC
    const vcPayload = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential", credentialType],
      issuer: enteKeys.issuerDid,
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: request.senderDID,
        message: "✅ Registrazione accettata!"
      }
    };

    // 🔐 Chiavi crittografiche
    const clientPublicCryptoKeyBytes = await this.extractKeyAgreementKeyBytes(request.didDocument, "X25519");
    const entePrivateCryptoKeyBytes = Buffer.from(enteKeys.privateCryptoKey, "base64");

    // 📝 Canonicalizzazione e firma
    const canonicalVC = canonicalize(vcPayload);
    const vcBytes = new TextEncoder().encode(canonicalVC);
    const signature = nacl.sign.detached(vcBytes, Buffer.from(enteKeys.privateSignKey, "base64"));

    // 🧾 VC firmata (proof include canonical payload)
    const signedVC = {
      ...vcPayload,
      proof: {
        type: "Ed25519Signature2018",
        created: new Date().toISOString(),
        proofPurpose: "assertionMethod",
        verificationMethod: `${enteKeys.issuerDid}#key-1`,
        signatureValue: Buffer.from(signature).toString('base64'),
        canonicalPayload: canonicalVC
      }
    };

    // 🔒 Crittografia
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const signedVCBytes = new TextEncoder().encode(JSON.stringify(signedVC));

    const encryptedMessageBytes = nacl.box(
      signedVCBytes,
      nonce,
      clientPublicCryptoKeyBytes,
      entePrivateCryptoKeyBytes
    );

    const encryptedResponse = {
      nonce: naclUtil.encodeBase64(nonce),
      ciphertext: naclUtil.encodeBase64(encryptedMessageBytes),
      issuerPublicCryptoKey: this.serverSetup.entePublicCryptoKey,
      issuerPublicSignKey: enteKeys.publicSignKey
    };

    //console.log("🚀 Invio al client sulla porta:", request.clientPort);
    //console.log("📦 Payload VC in uscita:");
    //console.log(JSON.stringify(encryptedResponse, null, 2));

    const clientURL = `http://localhost:${request.clientPort}`;
    await axios.post(`${clientURL}/receive-server-vc`, encryptedResponse);

    console.log("✅ VC inviata al client!");
    return { status: "success" };

  } catch (error) {
    console.error("❌ Errore nell'elaborazione della richiesta:", error.message);
  }
}

 creaEvidence(clientFiles, clientFolderPath) {
  console.log("🔎 clientFiles dentro creaEvidence:", clientFiles);

  return clientFiles.map(fileName => {
    const filePath = path.join(clientFolderPath, fileName);

    let sha256 = "⚠️ non calcolabile";
    if (fs.existsSync(filePath)) {
      const buffer = fs.readFileSync(filePath);
      sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    }

    return {
      type: "DocumentReference",
      fileName,
      sha256
    };
  });
}
async sendDataToClient(request, enteKeys,parentFolder,credentialType) {
  try {
    
    const {clientFiles,matchedFolder}= this.serverSetup.listClientFiles(request.client_username,parentFolder);
    if (clientFiles.length === 0) {
      console.warn("⚠️ Nessun file allegato. Proseguo solo con la VC.");
    }
    const clientFolderPath = path.join(parentFolder, matchedFolder);
    const evidence = this.creaEvidence(clientFiles, clientFolderPath);
    console.log("📂 Risultato da listClientFiles:");
    console.log("→ matchedFolder:", matchedFolder);
    console.log("→ clientFiles:", clientFiles); // dovrebbe essere un array!
    const formattedDID = typeof request.senderDID === "object" 
      ? JSON.stringify(request.senderDID, null, 2) 
      : request.senderDID;

    const formattedDidDocument = typeof request.didDocument === "object" 
      ? JSON.stringify(request.didDocument, null, 2) 
      : request.didDocument;

    //console.log(`✅ Registrazione ricevuta da: ${formattedDID}`);
    //console.log("📄 DID Document:", formattedDidDocument);

    

    // 🎫 Costruzione VC
    const vcPayload = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential", credentialType],
      issuer: enteKeys.issuerDid,
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: request.senderDID,
        message: "Invio di Dati richiesti",
        fileCount: clientFiles.length, // opzionale, ma utile
          documentType: credentialType // ← nuova proprietà
      },
      evidence: evidence
    };

    // 🔐 Chiavi crittografiche
    const clientPublicCryptoKeyBytes = await this.extractKeyAgreementKeyBytes(request.didDocument, "X25519");
    const entePrivateCryptoKeyBytes = Buffer.from(enteKeys.privateCryptoKey, "base64");

    // 📝 Canonicalizzazione e firma
    const canonicalVC = canonicalize(vcPayload);
    const vcBytes = new TextEncoder().encode(canonicalVC);
    const signature = nacl.sign.detached(vcBytes, Buffer.from(enteKeys.privateSignKey, "base64"));

    // 🧾 VC firmata (proof include canonical payload)
    const signedVC = {
      ...vcPayload,
      proof: {
        type: "Ed25519Signature2018",
        created: new Date().toISOString(),
        proofPurpose: "assertionMethod",
        verificationMethod: `${enteKeys.issuerDid}#key-1`,
        signatureValue: Buffer.from(signature).toString('base64'),
        canonicalPayload: canonicalVC
      }
    };

    // 🔒 Crittografia
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const signedVCBytes = new TextEncoder().encode(JSON.stringify(signedVC));

    const encryptedMessageBytes = nacl.box(
      signedVCBytes,
      nonce,
      clientPublicCryptoKeyBytes,
      entePrivateCryptoKeyBytes
    );

    const encryptedResponse = {
      nonce: naclUtil.encodeBase64(nonce),
      ciphertext: naclUtil.encodeBase64(encryptedMessageBytes),
      issuerPublicCryptoKey: this.serverSetup.entePublicCryptoKey,
      issuerPublicSignKey: enteKeys.publicSignKey
    };

    //console.log("🚀 Invio al client sulla porta:", request.clientPort);
    //console.log("📦 Payload VC in uscita:");
    //console.log(JSON.stringify(encryptedResponse, null, 2));

    const form = new FormData();
    form.append('vc', JSON.stringify(encryptedResponse));

    clientFiles.forEach(fileName => {
      const filePath = path.join(clientFolderPath, fileName);
      console.log("📎 Allegato preparato:", filePath);
      form.append('allegati', fs.createReadStream(filePath), fileName);
    });

    const clientURL = `http://localhost:${request.clientPort}`;
    await axios.post(`${clientURL}/receive-server-data`, form, {
      headers: form.getHeaders()
    });

console.log("✅ VC + allegati inviati al client!");


    console.log("✅ VC inviata al client!");
    return { status: "success" };

  } catch (error) {
    console.error("❌ Errore nell'elaborazione della richiesta:", error.message);
  }
}
  

async extractPublicKeyBytes(didDoc, crv) {
  const verificationMethods = didDoc.verificationMethod || [];

  // Cerca il metodo giusto in base al tipo
  const matchType = crv === 'Ed25519'
    ? 'Ed25519VerificationKey2018'
    : crv === 'X25519'
    ? 'X25519KeyAgreementKey2019'
    : null;

  if (!matchType) throw new Error(`❌ Curva non supportata: ${crv}`);

  const vm = verificationMethods.find(k => k.type === matchType);

  if (!vm) throw new Error(`❌ Nessuna verificationMethod trovata per tipo: ${matchType}`);

  if (!vm.publicKeyHex) throw new Error(`❌ Chiave mancante: expected publicKeyHex for ${matchType}`);

  return Buffer.from(vm.publicKeyHex, 'hex');
}
async extractKeyAgreementKeyBytes(didDoc, crv) {
  const keyAgreements = didDoc.keyAgreement || [];

  const matchType = crv === "X25519"
    ? "X25519KeyAgreementKey2019"
    : null;

  const vm = keyAgreements.find(k => k.type === matchType);
  if (!vm) throw new Error(`❌ Nessuna keyAgreement trovata per tipo: ${matchType}`);

  if (!vm.publicKeyHex) throw new Error(`❌ Nessun campo publicKeyHex in keyAgreement`);

  return Buffer.from(vm.publicKeyHex, "hex");
}

async getPublicKeyByDID(did,resolverUrl) {
  try {
    //console.log(`🔍 Richiesta chiave pubblica per DID: ${did}`);
    const response = await axios.get(`${resolverUrl}/resolve/${did}`);

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
async verifyVP(vp, serverSp, signature, senderPublicSignKey) {
  try {
    if (!vp || !senderPublicSignKey || !signature) {
      throw new Error("VP, chiave pubblica o firma mancante");
    }

    // 🔍 Stampe preventive
    //console.log("🧾 Firma (hex):", signature);
    //console.log("📏 Lunghezza firma (caratteri):", signature.length);
    //console.log("🔐 Chiave pubblica CLIENT (base64):", senderPublicSignKey);
    //console.log("📏 Lunghezza chiave pubblica (caratteri):", senderPublicSignKey.length);

    // Cloniamo la VP e rimuoviamo il proof (che contiene la firma stessa)
    const vpCopy = JSON.parse(JSON.stringify(vp));
    if (vpCopy.proof) {
      delete vpCopy.proof;
    }

    const vpStringToVerify = JSON.stringify(vpCopy);
    const vpBytes = new TextEncoder().encode(vpStringToVerify);
    const signatureBytes = new Uint8Array(Buffer.from(signature, 'hex'));
    const publicKeyBytes = new Uint8Array(Buffer.from(senderPublicSignKey, 'hex'));

    // 🧪 Debug finale
    //console.log("📝 [SERVER] VP stringata (per verifica):", vpStringToVerify);
    //console.log("📏 Lunghezza stringa:", vpStringToVerify.length);
    //console.log("📐 Lunghezza firma (bytes):", signatureBytes.length);
    //console.log("📐 Lunghezza chiave pubblica (bytes):", publicKeyBytes.length);

    const valid = nacl.sign.detached.verify(vpBytes, signatureBytes, publicKeyBytes);
    return valid;

  } catch (error) {
    console.error("❌ Errore nella verifica della VP:", error.stack);
    return false;
  }
}





decryptVP(encryptedVP, serverPrivateCryptoKeyBase64, senderPublicCryptoKeyBase64) {
  try {
    //console.log("📦 Encrypted VP ricevuta:");
    //console.log(JSON.stringify(encryptedVP, null, 2));

    // 🔐 Decodifica chiave privata
    //console.log("🧾 Chiave privata (Base64):", serverPrivateCryptoKeyBase64);
    const privateKeyBytes = naclUtil.decodeBase64(serverPrivateCryptoKeyBase64);
    //console.log("📏 Lunghezza chiave privata (byte):", privateKeyBytes.length);
    //console.log("🔑 Chiave privata (hex):", Buffer.from(privateKeyBytes).toString('hex'));

    // 🔓 Decodifica chiave pubblica del mittente
    //console.log("🔓 Chiave pubblica mittente (Base64):", senderPublicCryptoKeyBase64);
    const publicKeyBytes = new Uint8Array(Buffer.from(senderPublicCryptoKeyBase64, 'hex'));

    //console.log("📏 Lunghezza chiave pubblica (byte):", publicKeyBytes.length);
    //console.log("🔓 Chiave pubblica (hex):", Buffer.from(publicKeyBytes).toString('hex'));

    // 📥 Estrai e decodifica nonce e ciphertext
    const { nonce: nonceBase64, ciphertext: ciphertextBase64 } = encryptedVP;

    //console.log("📎 Nonce (Base64):", nonceBase64);
    //console.log("📎 Ciphertext (Base64):", ciphertextBase64);

    const nonce = naclUtil.decodeBase64(nonceBase64);
    const ciphertext = naclUtil.decodeBase64(ciphertextBase64);

    //console.log("📐 Lunghezza nonce:", nonce.length);
    //console.log("📐 Lunghezza ciphertext:", ciphertext.length);

    // 🛡️ Prova decrittazione
    const decryptedBytes = nacl.box.open(ciphertext, nonce, publicKeyBytes, privateKeyBytes);

    if (!decryptedBytes) {
      throw new Error("Decrittazione fallita: nonce, chiavi o ciphertext non corrispondenti");
    }

    const decryptedString = naclUtil.encodeUTF8(decryptedBytes);
    console.log("✅ VP decrittata:");

    return JSON.parse(decryptedString);

  } catch (err) {
    console.error("❌ Errore durante la decrittazione della VP:");
    console.error("📍 Messaggio:", err.message);
    console.error("🪵 Stack trace:", err.stack);
    throw err; // rilancia per la funzione chiamante
  }
}



async registerClientOnResolver(clientDID, fiscalCode, signKeyBase64, cryptoKeyBase64) {
  const RESOLVER_ENDPOINT = 'http://localhost:4000/register-client';

  try {
    const response = await fetch(RESOLVER_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        did: clientDID,
        encryptionPublicKey: cryptoKeyBase64,
        signingPublicKey: signKeyBase64,
        fiscalCode: fiscalCode
      })
    });

    const contentType = response.headers.get('content-type');
    const isJson = contentType && contentType.includes('application/json');
    const data = isJson ? await response.json() : null;

    if (response.status === 409) {
      return { status: 'duplicate', message: data?.message || 'CF già registrato' };
    }

    if (response.ok) {
      return { status: 'ok', did: data?.did, message: data?.message || 'Registrazione avvenuta' };
    }

    return {
      status: 'error',
      message: data?.message || `Errore ${response.status}`,
      code: response.status
    };

  } catch (err) {
    return {
      status: 'network_error',
      message: err.message
    };
  }
}



async viewRegistrations() {
  const results = [];

  for (const [index, req] of this.registrationRequests.entries()) {
    try {
      console.log("\n====================================");
      console.log(`🔢 [${index + 1}] Richiesta ricevuta da:`, req.senderDID);

      const rawDidDoc = req.didDocument?.didDocument || req.didDocument;
      console.log("📄 DID Document ricevuto:", JSON.stringify(rawDidDoc, null, 2));

      if (!rawDidDoc?.verificationMethod) {
        throw new Error("❌ verificationMethod mancante nel DID Document!");
      }

      // Estrazione delle chiavi con logging
      const clientCryptoKeyBytes = await this.extractKeyAgreementKeyBytes(rawDidDoc, "X25519");
      const clientSignKeyBytes = await this.extractPublicKeyBytes(rawDidDoc, "Ed25519");
      console.log("✍️ Pubblica di firma (Ed25519):", clientSignKeyBytes);

      // Decodifica componenti
      const ciphertextBytes = naclUtil.decodeBase64(req.encryptedMessage.ciphertext);
      const nonceBytes = naclUtil.decodeBase64(req.encryptedMessage.nonce);
      const serverPrivateKeyBase64 = this.serverSetup.getPrivateCryptoKey();
      const serverPrivateKeyBytes = naclUtil.decodeBase64(serverPrivateKeyBase64);

      console.log("📦 Ciphertext base64:", req.encryptedMessage.ciphertext);
      console.log("🧂 Nonce base64:", req.encryptedMessage.nonce);
      

      // 🔓 Decriptazione
      console.log(`📨 Chiave pubblica del client (X25519): Uint8Array(${clientCryptoKeyBytes.length}) [\n  ${Array.from(clientCryptoKeyBytes).map((b, i) => (i % 8 === 0 && i > 0 ? '\n  ' : '') + b.toString().padStart(3)).join(', ')}\n]`);

      //console.log(`🔐 Chiave privata del server (X25519): Uint8Array(${serverPrivateKeyBytes.length}) [ ${Array.from(serverPrivateKeyBytes).join(', ')} ]`);

      const decryptedBytes = nacl.box.open(ciphertextBytes, nonceBytes, clientCryptoKeyBytes, serverPrivateKeyBytes);
      if (!decryptedBytes) {
        console.warn("🛑 ⚠️ Decriptazione fallita! Possibile mismatch tra chiavi?");
        throw new Error("❌ Decriptazione fallita!");
      }

      const decryptedText = naclUtil.encodeUTF8(decryptedBytes);
      const vc = JSON.parse(decryptedText);
      console.log("🔎 VC decriptata:", JSON.stringify(vc, null, 2));


      // 🔍 Validazione completa della struttura VC
      if (!vc || typeof vc !== 'object') {
        throw new Error("❌ La Verifiable Credential non è un oggetto valido.");
      }

      if (!vc["@context"] || !Array.isArray(vc["@context"])) {
        throw new Error("❌ Campo '@context' mancante o non valido.");
      }

      if (!vc.type || !Array.isArray(vc.type) || !vc.type.includes("VerifiableCredential")) {
        throw new Error("❌ Campo 'type' mancante o non contiene 'VerifiableCredential'.");
      }

      if (!vc.issuanceDate || typeof vc.issuanceDate !== "string") {
        throw new Error("❌ Campo 'issuanceDate' mancante o non valido.");
      }

      if (!vc.credentialSubject || typeof vc.credentialSubject !== "object") {
        throw new Error("❌ Campo 'credentialSubject' mancante o non valido.");
      }

      if (!vc.credentialSubject.fiscal_code) {
        throw new Error("❌ Campo 'fiscal_code' mancante in 'credentialSubject'.");
      }


      // ✔️ Verifica firma
      const messageBytes = naclUtil.decodeUTF8(decryptedText);
      const signatureBytes = Buffer.from(req.signature, "hex");
      const isValid = nacl.sign.detached.verify(messageBytes, signatureBytes, clientSignKeyBytes);

      console.log("✍️ Firma ricevuta:", req.signature);
      console.log("🔍 Verifica firma:", isValid ? "✅ Firma valida" : "❌ Firma NON valida");

      results.push({
        number: index + 1,
        senderDID: req.senderDID?.did || req.senderDID?.id || "N/A",
        timestamp: req.timestamp,
        decryptedMessage: decryptedText,
        signatureValid: isValid ? "✅ Valida" : "❌ NON valida",
        ClientPort:req.clientPort,
        codice_fiscale:vc.credentialSubject.fiscal_code,
        didDocument:rawDidDoc,
        clientUs:req.clientUs
      });

    } catch (error) {
      console.error(`⚠️ Errore nella richiesta [${index + 1}] — ${error.message}`);
      console.error("❌ Stack trace completo:", error?.stack || error);


      results.push({
        number: index + 1,
        senderDID: req.senderDID?.did || "N/A",
        timestamp: req.timestamp,
        decryptedMessage: "❌ Errore nella decriptazione",
        signatureValid: "❌ Errore"
      });
    }
  }

  console.log("\n📋 Risultati completati:", results.length);
  return results;
}

 calcolaHashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);

    stream.on('error', err => reject(`Errore nella lettura del file: ${err.message}`));
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => {
      const digest = hash.digest('hex');
      resolve(digest);
    });
  });
}
async showReceivedVPs(rl, server, entePrivateCryptoKey) {
  if (!server.verifier_accepted_requests || server.verifier_accepted_requests.length === 0) {
    console.log("📭 Nessuna VP ricevuta e memorizzata.");
    return;
  }

  console.log("\n🔎 Decifrando e verificando le VP ricevute...");

  for (let i = 0; i < server.verifier_accepted_requests.length; i++) {
    const requestEntry = server.verifier_accepted_requests[i];
    const vpEncrypted = requestEntry.request;
    const saveDir = requestEntry.saveDir;

    try {
      const {
        encryptedMessage,
        senderPublicEncryptionKey,
        senderDID,
        signature,
        senderPublicSignKey
      } = vpEncrypted;

      if (!encryptedMessage || !senderPublicEncryptionKey) {
        throw new Error("Messaggio cifrato o chiave pubblica mittente mancante");
      }

      const decryptedVP = await this.decryptVP(
        encryptedMessage,
        entePrivateCryptoKey,
        senderPublicEncryptionKey
      );

      console.log(`\n🔓 VP #${i + 1} decriptata da: ${senderDID}`);

      const isValidVP = await this.verifyVP(decryptedVP, server, signature, senderPublicSignKey);
      if (!isValidVP) {
        console.log(`❌ Firma VP #${i + 1} non valida!`);
        continue;
      }

      const areValidVCs = await this.verifyVCsInVP(decryptedVP);
      if (!areValidVCs) {
        console.log(`❌ VC non valide nella VP #${i + 1}`);
        continue;
      }

      const credentials = decryptedVP.verifiableCredential;
      console.log(`✅ VP #${i + 1} valida!`);
      console.log(`👤 Mittente: ${senderDID}`);
      console.log(`🔐 Tipo VP: ${decryptedVP.type?.join(", ")}`);
      console.log(`📄 Credential contenute: ${credentials.length}`);

      const embeddedFiles = decryptedVP.embeddedFiles || [];

      for (let j = 0; j < credentials.length; j++) {
        const vc = credentials[j];
        const subject = vc.credentialSubject || {};
        const evidence = vc.evidence || [];

        console.log(`\n  🪪 VC #${j + 1}:`);
        console.log(`  🔖 Tipo: ${vc.type?.join(", ")}`);
        console.log(`  🏢 Issuer: ${vc.issuer}`);
        console.log(`  📅 Data emissione: ${vc.issuanceDate}`);
        console.log(`  👤 Soggetto: ${subject.id}`);
        console.log(`  📋 Messaggio: ${subject.message}`);
        console.log(`  🗂️ Documento: ${subject.documentType}`);
        console.log(`  📎 File dichiarati: ${subject.fileCount}`);

        if (evidence.length > 0) {
          console.log(`  🧾 Evidence dichiarate:`);
          evidence.forEach((ev, idx) => {
            console.log(`    ${idx + 1}. ${ev.fileName} (SHA-256: ${ev.sha256})`);
          });
        }

        if (evidence.length > 0 && saveDir) {
          console.log(`  🔍 Verifica integrità dei file salvati:`);

          for (const ev of evidence) {
            const filePath = path.join(saveDir, ev.fileName);
            if (!fs.existsSync(filePath)) {
              console.warn(`    ⚠️ ${ev.fileName} non trovato in ${saveDir}`);
              continue;
            }

            try {
              const calculatedHash = await this.calcolaHashFile(filePath);
              if (calculatedHash === ev.sha256) {
                console.log(`    ✅ ${ev.fileName}: hash corrisponde`);
              } else {
                console.log(`    ❌ ${ev.fileName}: hash NON corrisponde!`);
                console.log(`       ➤ Calcolato:  ${calculatedHash}`);
                console.log(`       ➤ Dichiarato: ${ev.sha256}`);
              }
            } catch (err) {
              console.error(`    ❌ Errore nel calcolo hash di ${ev.fileName}:`, err);
            }
          }
        }
      }

      if (embeddedFiles.length > 0) {
        console.log(`\n📦 Allegati incorporati nella VP: ${embeddedFiles.length} file`);
        embeddedFiles.forEach((file, idx) => {
          const name = file.fileName || "Sconosciuto";
          const size = file.base64Content
            ? Buffer.from(file.base64Content, 'base64').length
            : 0;
          console.log(`  📄 ${idx + 1}. ${name} (${size} byte)`);
        });

        const sceltaFile = await new Promise(resolve =>
          rl.question("📄 Inserisci il numero del file da aprire (0 per annullare): ", resolve)
        );

        const fileIdx = parseInt(sceltaFile, 10) - 1;
        if (fileIdx >= 0 && fileIdx < embeddedFiles.length) {
          const selectedFile = embeddedFiles[fileIdx];
          const fullPath = path.join(saveDir, selectedFile.fileName || `allegato_${fileIdx}.bin`);

          if (!fs.existsSync(fullPath)) {
            console.warn("⚠️ Il file selezionato non esiste in saveDir.");
          } else {
            exec(`xdg-open "${fullPath}"`, err => {
              if (err) {
                console.error("❌ Errore nell'apertura del file:", err.message);
              } else {
                console.log("📄 File aperto con successo!");
              }
            });
          }
        } else {
          console.log("❎ Nessun file aperto.");
        }
      }

    } catch (error) {
      console.error(`❌ Errore nella VP #${i + 1}:`, error.message);
    }
  }
}




 async getPublicSigningKeyByDID(did, resolverUrl) {
  try {
    console.log(`🔎 Recupero della chiave pubblica di firma per DID ${did}...`);
    const response = await axios.get(`${resolverUrl}/signing-key/${did}`);
    console.log("✅ Chiave pubblica di firma ricevuta:", response.data.signingKey);
    return response.data.signingKey;
  } catch (error) {
    console.error("❌ Errore nel recupero della chiave pubblica di firma:", error.message);
    return null;
  }
}
async verifyVCsInVP(vp) {
  if (!vp.verifiableCredential || !Array.isArray(vp.verifiableCredential)) {
    console.log("⚠️ Nessuna VC trovata nella VP");
    return false;
  }

  for (let i = 0; i < vp.verifiableCredential.length; i++) {
    console.log(`\n🔍 Verifica VC #${i + 1}`);

    const vc = vp.verifiableCredential[i];
    const { issuer, proof } = vc;

    if (!issuer) {
      console.log(`❌ VC #${i + 1} manca il campo 'issuer'`);
      return false;
    }
    if (!proof || !proof.signatureValue || !proof.canonicalPayload) {
      console.log(`❌ VC #${i + 1} manca 'proof.signatureValue' o 'proof.canonicalPayload'`);
      return false;
    }

    const vcCanonicalString = proof.canonicalPayload;
    const vcBytes = new TextEncoder().encode(vcCanonicalString);

    let signatureBytes;
    try {
      signatureBytes = Buffer.from(proof.signatureValue, 'base64');
    } catch (err) {
      console.log(`❌ Errore decodifica firma base64 VC #${i + 1}:`, err.message);
      return false;
    }

    const resolverUrl = "http://localhost:4000";
    let issuerPublicKeyBase64;
    try {
      issuerPublicKeyBase64 = await this.getPublicSigningKeyByDID(issuer, resolverUrl);
    } catch (err) {
      console.log(`❌ Errore recupero chiave pubblica issuer VC #${i + 1}:`, err.message);
      return false;
    }

    let publicKeyBytes;
    try {
      publicKeyBytes = Buffer.from(issuerPublicKeyBase64, 'base64');
    } catch (err) {
      console.log(`❌ Errore decodifica chiave pubblica base64 VC #${i + 1}:`, err.message);
      return false;
    }

    // Log diagnostici dettagliati
    //console.log("📝 VC canonicalizzata (inviata dall’issuer):");
    //console.log(vcCanonicalString);
    //console.log(`📏 Lunghezza VC canonical (caratteri): ${vcCanonicalString.length}`);
    //console.log("🔐 SHA-256 della VC canonicalizzata:", createHash('sha256').update(vcCanonicalString).digest('hex'));
    //console.log("🧾 Firma (base64):", proof.signatureValue);
    //console.log("📐 Lunghezza firma (bytes):", signatureBytes.length);
    //console.log("🔐 Chiave pubblica issuer (base64):", issuerPublicKeyBase64);
    //console.log("📐 Lunghezza chiave pubblica (bytes):", publicKeyBytes.length);
    //console.log("🔐 Firma bytes (hex):", signatureBytes.toString('hex'));
    //console.log("🔐 Chiave pubblica bytes (hex):", publicKeyBytes.toString('hex'));

    const isValid = nacl.sign.detached.verify(vcBytes, signatureBytes, publicKeyBytes);

    if (!isValid) {
      console.log(`❌ Firma non valida per VC #${i + 1}`);
      return false;
    }

    console.log(`✅ Firma valida per VC #${i + 1}`);
  }

  return true;
}









}

