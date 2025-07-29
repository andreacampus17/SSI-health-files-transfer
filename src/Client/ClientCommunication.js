import axios from 'axios';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
import express from 'express';
import { Resolver } from 'did-resolver';
import { getDidKeyResolver } from '@veramo/did-provider-key';
import { createAgent } from '@veramo/core';
import { DIDResolverPlugin } from '@veramo/did-resolver';
import canonicalize from 'canonicalize';
import { createHash } from 'crypto';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

import path from 'path';
import fs from 'fs'; 
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


export class ClientCommunication {
  constructor(clientSetup,rl) {
    this.clientSetup = clientSetup; // 🔹 Collegamento con il client
    this.app = express();
    this.app.use(express.json());
    this.rl = rl;
    //this.setupEndpoints(); // 🔹 Configura l'endpoint API
  }

  /*setupEndpoints() {
    this.app.post("/receive-server-vc", (req, res) => {
      console.log("📨 Richiesta VC ricevuta!");
      try {
        this.processReceivedVC(req.body, res, this.clientSetup.clientPrivateCryptoKey);
      } catch (error) {
        console.error("❌ Errore nel salvataggio della VC:", error.message);
        res.status(500).json({ error: "❌ Errore interno del server!" });
      }
    });

    this.app.listen(this.clientSetup.clientPort, () => {
      console.log(`🚀 Client in ascolto sulla porta ${this.clientSetup.clientPort}`);
    });
  }*/

  


  async encryptAndSendMessage(client_username,didClient,didDocument, vc, didEnte, clientPrivateCryptoKey, clientPublicCryptoKey, clientPrivateSignKey, clientPublicSignKey, resolverUrl,clientPort) {
    try {
      

      if (didDocument) {
        //console.log("🧾 Documento DID risolto:");
        //console.log(JSON.stringify(didDocument, null, 2));
      }
      console.log("🖊️ Firma del messaggio con chiave privata di firma del client...");
      if (!vc || typeof vc !== 'string') {
        console.error("❌ Errore: la VC non è valida!");
        return;
      }
      console.log("🔍 Controllo clientPrivateSignKey:", clientPrivateSignKey);
      if (!clientPrivateSignKey) {
        console.error("❌ Errore: chiave privata di firma non trovata!");
        return;
      }
      const server_port = this.clientSetup.serverPort;
      const server_url = `http://localhost:${server_port}/receive-message`;
      //console.log("🧐 URL generato:", server_url);

      const clientPrivateSignKeyBytes = new Uint8Array(Buffer.from(clientPrivateSignKey, 'hex'));
      const messageBytes = naclUtil.decodeUTF8(vc);
      const clientSignature = nacl.sign.detached(messageBytes, clientPrivateSignKeyBytes);

      //console.log("🔐 Cifratura del messaggio firmato con chiave pubblica dell'ente...");
      // ...
      //console.log("🔐 Cifratura del messaggio firmato con chiave pubblica dell'ente...");
      const entePublicCryptoKey = await this.getPublicKeyByDID(didEnte, resolverUrl);
      if (!entePublicCryptoKey) {
        console.log("❌ Chiave pubblica dell'ente non trovata!");
        return;
      }
      const entePublicCryptokeyBytes = new Uint8Array(Buffer.from(entePublicCryptoKey, 'base64'));


      

      const clientPrivateCryptoKeyBytes = new Uint8Array(Buffer.from(clientPrivateCryptoKey, 'hex'));


      const nonce = nacl.randomBytes(nacl.box.nonceLength);
      const encryptedMessageBytes = nacl.box(
        messageBytes,
        nonce,
        entePublicCryptokeyBytes,
        clientPrivateCryptoKeyBytes
      );
      console.log("clientPrivateCryptoKeyBytes:", clientPrivateCryptoKeyBytes);
      console.log("entePublicCryptokeyBytes:", entePublicCryptokeyBytes);
      //console.log("clientPublicCryptoKeyBytes:", clientPublicCryptoKey);
      
      const keyBytes = new Uint8Array(Buffer.from(this.clientSetup.clientPublicCryptoKey, 'hex'));
      console.log(`🔐 clientPublicCryptoKeyBytes: Uint8Array(${this.clientSetup.clientPublicCryptoKey.length}) [ ${Array.from(keyBytes).join(', ')} ]`);


      const encryptedMessage = {
        nonce: naclUtil.encodeBase64(nonce),
        ciphertext: naclUtil.encodeBase64(encryptedMessageBytes)
      };
      /*console.log("📤 Dati che verranno inviati al server:");
      console.log("🔐 Encrypted Message:", encryptedMessage);
      console.log("🖊️ Firma (hex):", Buffer.from(clientSignature).toString('hex'));
      console.log("🧾 senderDID:", didClient);
      console.log("📄 didDocument:", JSON.stringify(didDocument, null, 2));
      console.log("🚪 clientPort:", clientPort);*/

      const response = await axios.post(server_url, {
        encryptedMessage,
        signature: Buffer.from(clientSignature).toString('hex'),
        senderDID: didClient,
        didDocument,
        clientPort:clientPort,
        clientUs: client_username
      });
      
      console.log("✅ Messaggio firmato, criptato e inviato con successo!", response.data);
    } catch (error) {
      console.error("❌ Errore durante la firma o la cifratura:", error.message);
    }
  }
async verifyChallenge(clientPort,did,didDocument, challenge, clientPrivateKeyHex, serverUrl,client_username) {
  try {
    // Encode challenge
    const encodedChallenge = new TextEncoder().encode(challenge);

    // Convert private key from hex to Uint8Array
    const privateKeyBytes = new Uint8Array(Buffer.from(clientPrivateKeyHex, "hex"));

    // Firma la challenge
    const signature = nacl.sign.detached(encodedChallenge, privateKeyBytes);

    // Prepara il payload
    const payload = {
      did,
      challenge,
      signature: Buffer.from(signature).toString("base64"),
      client_username,
      didDocument,
      clientPort
    };

    // Manda la verifica al server
    const response = await fetch(`${serverUrl}/verify-challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Verifica fallita: ${errorText}`);
    }

    console.log("Autenticazione riuscita!");
    return true;
  } catch (err) {
    console.error("Errore nella verifica della challenge:", err);
    return false;
  }
}

  async getPublicKeyByDID(did, resolverUrl) {
    try {
      console.log(`🔎 Recupero della chiave pubblica per DID ${did}...`);
      const response = await axios.get(`${resolverUrl}/resolve/${did}`);
      console.log("✅ Chiave pubblica ricevuta:", response.data.publicKey);
      return response.data.publicKey;
    } catch (error) {
      console.error("❌ Errore nel recupero della chiave pubblica:", error.message);
      return null;
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
async processReceivedRegistrationResponse(vcData, res, clientPrivateCryptoKey, clientSetup) {
  try {
    console.log("📥 Ricezione della VC crittografata...");
    ///console.log("🔐 Payload ricevuto:", JSON.stringify(vcData, null, 2));

    // 1. Decodifica dei componenti criptati
    const nonce = naclUtil.decodeBase64(vcData.nonce);
    const ciphertext = naclUtil.decodeBase64(vcData.ciphertext);
    const issuerPublicCryptoKeyBytes = Buffer.from(vcData.issuerPublicCryptoKey, "base64");
    const clientPrivateCryptoKeyBytes = Buffer.from(clientPrivateCryptoKey, "hex");

    console.log("🔐 Componenti decodificati con successo.");

    // 2. Decriptazione
    const decryptedBytes = nacl.box.open(
      ciphertext,
      nonce,
      issuerPublicCryptoKeyBytes,
      clientPrivateCryptoKeyBytes
    );
    if (!decryptedBytes) throw new Error("❌ Decriptazione fallita!");

    // 3. Parsing del messaggio JSON decriptato
    const decryptedJson = naclUtil.encodeUTF8(decryptedBytes);
    const signedVC = JSON.parse(decryptedJson);
    console.log("✅ VC decrittata (parsed):", signedVC);

    // 4. Validazione campi di firma
    if (!signedVC.proof || !signedVC.proof.signatureValue || !signedVC.proof.verificationMethod) {
      throw new Error("❌ La VC decrittata non contiene un campo 'proof' valido con firma");
    }

    const signatureBytes = naclUtil.decodeBase64(signedVC.proof.signatureValue);
    const verificationMethod = signedVC.proof.verificationMethod;
    const did = verificationMethod.split('#')[0];

    // 5. Recupera chiave pubblica dell'issuer
    console.log("🔍 Recupero chiave pubblica dell'issuer:", did);
    const pubKeyBase64 = await this.getPublicSigningKeyByDID(did, 'http://localhost:4000');
    const pubKeyBytes = naclUtil.decodeBase64(pubKeyBase64);

    // 6. Verifica firma usando canonicalPayload fornito
    const canonicalPayload = signedVC.proof.canonicalPayload;
    if (!canonicalPayload) throw new Error("❌ canonicalPayload mancante nel campo 'proof'");

    const payloadBytes = naclUtil.decodeUTF8(canonicalPayload);

    const isValid = nacl.sign.detached.verify(
      payloadBytes,
      signatureBytes,
      pubKeyBytes
    );

    if (!isValid) {
      throw new Error("❌ Firma non valida! Il messaggio potrebbe essere stato alterato.");
    }

    console.log("✅ Firma verificata con successo!");

    // 7. Salvataggio della VC
    
    clientSetup.registrationResponses.push({
      full: signedVC,
      canonicalPayload: canonicalPayload
    });

    console.log(`📦 VC salvata! Totale archiviate: ${clientSetup.vcStorage.length}`);
    res.json({ message: "✅ VC decrittata, verificata e salvata con successo!" });

  } catch (error) {
    console.error("❌ Errore nella decriptazione o verifica firma:", error.message);
    res.status(500).json({ error: error.message });
  }
}

async processReceivedVC(vcData, res, clientPrivateCryptoKey, clientSetup,pathFolder) {
  try {
    console.log("📥 Ricezione della VC crittografata...");
    ///console.log("🔐 Payload ricevuto:", JSON.stringify(vcData, null, 2));

    // 1. Decodifica dei componenti criptati
    const nonce = naclUtil.decodeBase64(vcData.nonce);
    const ciphertext = naclUtil.decodeBase64(vcData.ciphertext);
    const issuerPublicCryptoKeyBytes = Buffer.from(vcData.issuerPublicCryptoKey, "base64");
    const clientPrivateCryptoKeyBytes = Buffer.from(clientPrivateCryptoKey, "hex");

    console.log("🔐 Componenti decodificati con successo.");

    // 2. Decriptazione
    const decryptedBytes = nacl.box.open(
      ciphertext,
      nonce,
      issuerPublicCryptoKeyBytes,
      clientPrivateCryptoKeyBytes
    );
    if (!decryptedBytes) throw new Error("❌ Decriptazione fallita!");

    // 3. Parsing del messaggio JSON decriptato
    const decryptedJson = naclUtil.encodeUTF8(decryptedBytes);
    const signedVC = JSON.parse(decryptedJson);
    console.log("✅ VC decrittata (parsed):", signedVC);

    // 4. Validazione campi di firma
    if (!signedVC.proof || !signedVC.proof.signatureValue || !signedVC.proof.verificationMethod) {
      throw new Error("❌ La VC decrittata non contiene un campo 'proof' valido con firma");
    }

    const signatureBytes = naclUtil.decodeBase64(signedVC.proof.signatureValue);
    const verificationMethod = signedVC.proof.verificationMethod;
    const did = verificationMethod.split('#')[0];

    // 5. Recupera chiave pubblica dell'issuer
    console.log("🔍 Recupero chiave pubblica dell'issuer:", did);
    const pubKeyBase64 = await this.getPublicSigningKeyByDID(did, 'http://localhost:4000');
    const pubKeyBytes = naclUtil.decodeBase64(pubKeyBase64);

    // 6. Verifica firma usando canonicalPayload fornito
    const canonicalPayload = signedVC.proof.canonicalPayload;
    if (!canonicalPayload) throw new Error("❌ canonicalPayload mancante nel campo 'proof'");

    const payloadBytes = naclUtil.decodeUTF8(canonicalPayload);

    const isValid = nacl.sign.detached.verify(
      payloadBytes,
      signatureBytes,
      pubKeyBytes
    );

    if (!isValid) {
      throw new Error("❌ Firma non valida! Il messaggio potrebbe essere stato alterato.");
    }

    console.log("✅ Firma verificata con successo!");

    // 7. Salvataggio della VC
    clientSetup.vcStorage.push({
      full: signedVC,
      canonicalPayload: canonicalPayload,
      signatureVerified: true,// ✅ salva lo stato!
      pathFolder
    });

    console.log(`📦 VC salvata! Totale archiviate: ${clientSetup.vcStorage.length}`);
    res.json({ message: "✅ VC decrittata, verificata e salvata con successo!" });

  } catch (error) {
    console.error("❌ Errore nella decriptazione o verifica firma:", error.message);
    res.status(500).json({ error: error.message });
  }
}




  async resetServerPort() {
    console.log("🔄 Reset della porta del server...");
    this.serverPort = await this.askServerPort();
    console.log(`✅ Nuova porta del server impostata: ${this.serverPort}`);
  }



  extractEmbeddedFilesFromVC(vc, pathFolder) {


  if (!vc || !vc.evidence || !Array.isArray(vc.evidence)) {
    throw new Error("❌ VC mancante o campo 'evidence' non valido.");
  }

  const embeddedFiles = [];

  for (const item of vc.evidence) {
    const fileName = item.fileName;
    if (!fileName) continue;

    const fullPath = path.join(pathFolder, fileName);

    if (!fs.existsSync(fullPath)) {
      console.warn(`⚠️ File non trovato: ${fullPath}`);
      continue;
    }

    const fileBuffer = fs.readFileSync(fullPath);
    const base64Content = fileBuffer.toString('base64');

    embeddedFiles.push({
      fileName,
      base64Content
    });
  }

  return embeddedFiles;
}
 
async createAndSignVP(request, requestedType, verifierPublicCryptoKey, clientSetup,pathFolder) {
  if (!Array.isArray(clientSetup.vcStorage)) {
    console.error("❌ Nessuna VC archiviata! Impossibile creare la VP.");
    return;
  }
  
  // Prendi le VC complete (oggetti) dal tuo array di {full, canonicalPayload}
  const parsedVCs = clientSetup.vcStorage.map(vcEntry => vcEntry.full);

  const matchingVC = parsedVCs.find(vc => vc.type.includes(requestedType));
  const embeddedFiles = this.extractEmbeddedFilesFromVC(matchingVC, pathFolder);
  if (!matchingVC) {
    throw new Error(`❌ Nessuna VC trovata del tipo richiesto: ${requestedType}`);
  }

  // Stampiamo la VC completa
  const vcJsonString = JSON.stringify(matchingVC, null, 2);
  console.log("📝 VC JSON completa:");
  console.log(vcJsonString);
  //console.log(`📏 Lunghezza VC JSON (caratteri): ${vcJsonString.length}`);

  // Cloniamo e rimuoviamo proof per la canonicalizzazione
  const vcCopy = JSON.parse(JSON.stringify(matchingVC));
  delete vcCopy.proof;

  // Canonicalizziamo la VC (stringa usata per firma)
  const vcCanonicalString = canonicalize(vcCopy);
  console.log("📝 VC canonicalizzata:");
  console.log(vcCanonicalString);
  console.log(`📏 Lunghezza VC canonical (caratteri): ${vcCanonicalString.length}`);

  // Calcoliamo hash SHA-256 della VC canonicalizzata
  const vcCanonicalHash = createHash('sha256').update(vcCanonicalString).digest('hex');
  console.log("🔐 SHA-256 della VC canonicalizzata:", vcCanonicalHash);

  // Costruiamo la VP con la VC completa
  const vp = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiablePresentation"],
    verifiableCredential: [matchingVC],
    holder: clientSetup.identity.did,
    embeddedFiles
  };
  const vpId = this.generateVPHash(vp);
  vp.vpId = vpId;


  // Chiave privata client per firmare la VP
  const clientPrivateSignKeyBytes = new Uint8Array(Buffer.from(clientSetup.clientPrivateSignKey, 'hex'));

  // Firma la VP (la funzione signVP deve restituire {signedVP, signature, signatureHex})
  const { signedVP, signature, signatureHex } = await this.signVP(vp, clientPrivateSignKeyBytes, clientSetup.did);

  // Log firma
  //console.log("🧾 Firma della VP (base64):", signature);
  //console.log("📐 Lunghezza firma (bytes):", Buffer.from(signature, 'base64').length);

  return {
    signedVP,
    signature,
  };
}


async signVP(vp, privateKeyUint8Array, did) {
  console.log("✅ Tipo chiave:", typeof privateKeyUint8Array);
  console.log("✅ È Uint8Array?", privateKeyUint8Array instanceof Uint8Array);
  console.log("✅ Lunghezza:", privateKeyUint8Array.length);

  const vpString = JSON.stringify(vp);
  const vpBytes = new TextEncoder().encode(vpString);

  const signature = nacl.sign.detached(vpBytes, privateKeyUint8Array);

  //console.log("📝 [CLIENT] VP stringata (per firma):", vpString);
  //console.log("📏 Lunghezza stringa:", vpString.length);
  //console.log("🧾 Firma generata (hex):", Buffer.from(signature).toString('hex'));
  //console.log("📐 Lunghezza firma:", signature.length);

  const signedVP = {
    ...vp,
    proof: {
      type: "Ed25519Signature2018",
      created: new Date().toISOString(),
      proofPurpose: "authentication",
      verificationMethod: `${did}#key-1`,
      signatureValue: Buffer.from(signature).toString('base64')
    }
  };

  return {
    signedVP,
    signature, // Uint8Array
    signatureHex: Buffer.from(signature).toString('hex'),
    signatureBase64: Buffer.from(signature).toString('base64')
  };
}
 generateVPHash(vp) {
  const canonicalString = JSON.stringify(vp); // meglio: canonicalizzare se necessario
  const hash = crypto.createHash('sha256').update(canonicalString).digest('hex');
  return hash;
}
async  revocaPresentazione(index, clientSetup,vpID) {
  const vpInfo = clientSetup.authorizedPresentations[index];
  if (!vpInfo) {
    console.error("❌ Nessuna VP trovata all’indice specificato.");
    return;
  }

  const revokeRequest = {
    type: "VPRevocation",
    vpId: vpID,
    revokedAt: new Date().toISOString(),
    holder: clientSetup.identity.did
    };
  const privateKeyBytes = new Uint8Array(Buffer.from(clientSetup.clientPrivateSignKey, 'hex'));
  const publicKeyBytes = new Uint8Array(Buffer.from(clientSetup.clientPublicSignKey, 'hex'));

  const encoded = new TextEncoder().encode(JSON.stringify(revokeRequest));
  const signature = nacl.sign.detached(encoded, privateKeyBytes);
  const payload = {
    revokeRequest,
    signature: Buffer.from(signature).toString("base64"),
    publicKey: publicKeyBytes
  };

  try {
    console.log("Porta verifier: ",vpInfo.verifierPort);
    await fetch(`http://localhost:${vpInfo.verifierPort}/vp-revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    clientSetup.authorizedPresentations.splice(index, 1); // Rimuovi la VP
    console.log("✅ Revoca inviata al verifier e VP rimossa localmente.");
    console.log("Sto inviando questo: ",payload);
    return;
  } catch (err) {
    console.error("❌ Errore durante l’invio della revoca:", err.message);
  }
}

async sendVPtoVerifier(clientSetup,signature,verifierPort, vp, verifierPublicCryptoKey,clientPrivateCryptoKey,clientPublicEncryptKeyBase) {
  try {
    const url = `http://localhost:${verifierPort}/receive-vp`;

    // Converti VP in stringa JSON da cifrare
    const vpString = JSON.stringify(vp);

    // Qui devi prendere le chiavi del client (private crypto e private sign)
    // Supponiamo siano disponibili in clientSetup
    const clientPrivateCryptoKeyBytes = new Uint8Array(Buffer.from(clientPrivateCryptoKey, 'hex'));
    const clientPrivateSignKeyBytes = new Uint8Array(Buffer.from(this.clientSetup.clientPrivateSignKey, 'hex'));

    

    // Cifratura della VP firmata con la chiave pubblica crypto del verifier
    const verifierPublicCryptoKeyBytes = new Uint8Array(Buffer.from(verifierPublicCryptoKey, 'base64'));
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const vpBytes = new TextEncoder().encode(vpString);

    const encryptedMessageBytes = nacl.box(vpBytes, nonce, verifierPublicCryptoKeyBytes, clientPrivateCryptoKeyBytes);

    const encryptedMessage = {
      nonce: naclUtil.encodeBase64(nonce),
      ciphertext: naclUtil.encodeBase64(encryptedMessageBytes)
    };
    /*const realPublicKey = nacl.box.keyPair.fromSecretKey(clientPrivateCryptoKeyBytes).publicKey;
    console.log("📢 Public key derivata dalla private:", Buffer.from(realPublicKey).toString('hex'));
    console.log("📢 Public key inviata nel payload:", clientPublicEncryptKeyBase);*/


    // POST al verifier
    const response = await axios.post(url, {
      encryptedMessage,
      signature: Buffer.from(signature).toString('hex'),
      senderDID: clientSetup.identity.did,
      clientPort: clientSetup.clientPort,
      senderPublicEncryptionKey: clientPublicEncryptKeyBase, // 👈 ECCOLA QUI
      senderPublicSignKey: clientSetup.clientPublicSignKey,
      controller: clientSetup.controller

      // eventualmente includi altri dati se servono
    });

    console.log("✅ VP criptata e inviata al verifier con successo:", response.data);
  } catch (error) {
    console.error("❌ Errore nell'invio della VP criptata al verifier:", error.message);
  }
}

async dataRequest(serverUrl, did) {
  try {
    // Costruisco URL con DID codificato
    const url = `${serverUrl}/challenge/${encodeURIComponent(did)}`;

    // Invio richiesta GET per ricevere la challenge
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });

    if (!response.ok) {
      console.error(`Errore: ${response.status} - ${response.statusText}`);
      return null;
    }

    // Estraggo la challenge dal corpo
    const { challenge } = await response.json();
    console.log("Challenge ricevuta:", challenge);
    return challenge;

  } catch (error) {
    console.error("Errore nella richiesta dati:", error);
    return null;
  }
}


 

}
