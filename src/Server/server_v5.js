import readline from 'readline';
import fetch from 'node-fetch';
import express from 'express';
import { ServerSetup } from './serverSetup.js';
import { RegistrationManager } from './registrationManager.js';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
import fs from 'fs';

import session from 'express-session';
// 🌍 Da mettere in cima al file .js (solo se stai usando "type": "module" in package.json)
import { fileURLToPath } from 'url';
import path from 'path';

// ✅ Variabili globali
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const sessionSecret = process.env.SESSION_SECRET || 'default_segreto_per_sviluppo';

export class ServerManager {
  constructor() {
    // Nel setup di express-session

    this.rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    this.app = express();
    this.app.use(express.json());
    this.nacl = nacl;
        this.app.use(session({
      secret: sessionSecret,
      resave: false,
      saveUninitialized: true,
      cookie: { secure: false }
    }));
    this.server = new ServerSetup(this.rl,this.app);
    this.registrationManager = new RegistrationManager(this.rl,this.server);

    this.setupEndpoints(this.server); // 🔹 Configura gli endpoint API
  }

  setupEndpoints(server) {
this.app.post("/verify-challenge", async (req, res) => {
  console.log("Entro dentro verify-challenge");
      try {
        const {
      clientPort,
      did,
      didDocument,
      challenge,
      signature,
      client_username
    } = req.body;

    

    //const { clientPort,did,didDocument, challenge, signature, client_username } = req.body;
    console.log("📥 Payload ricevuto:");
    console.log("→ did:", did);
    console.log("→ challenge:", challenge);
    console.log("→ signature:", signature);

    if (!did || !challenge || !signature ) {
      return res.status(400).send("❌ Payload incompleto.");
    }

    // Controlla che la challenge sia quella corretta
    if (!this.registrationManager.challenges || this.registrationManager.challenges[did] !== challenge) {
      return res.status(400).send("❌ Challenge non valida o scaduta.");
    }

    if(this.registrationManager.challenges[did]!= challenge)
    {
      return res.status(401).send("⛔ Firma non valida.");
    }
    const resolverUrl = "http://localhost:4000";
    const clientPublicSignKey= await this.registrationManager.getPublicSigningKeyByDID(did,resolverUrl);
    // Ricodifica challenge e firma
    const encodedChallenge = new TextEncoder().encode(challenge);
    const signatureBytes = new Uint8Array(Buffer.from(signature, "base64"));
    const publicKeyBytes = Buffer.from(clientPublicSignKey, 'base64');

    // Verifica firma con nacl (Ed25519)
    const isValid = nacl.sign.detached.verify(
      encodedChallenge,
      signatureBytes,
      publicKeyBytes
    );

    if (!isValid) {
      return res.status(401).send("⛔ Firma non valida.");
    }

    // Rimuovi la challenge usata per evitare replay attack
    delete this.registrationManager.challenges[did];

    // Segna la sessione come autenticata
    this.server.sessions = this.server.sessions || {};
    this.server.sessions[did] = { authenticated: true, timestamp: Date.now() };

    //console.log(`✅ Utente ${did} autenticato con successo.`);
    console.log("Invio dei dati!");
    const request = {
      senderDID: did,                         // Es: const did = ...;
      didDocument: didDocument,              // Es: const didDocument = ...;
      challenge: challenge,                  // Es: const challenge = ...;
      signature: signature,                  // Es: const signature = ...;
      client_username: client_username,      // Es: const client_username = ...;
      credentialType: " ",        // Es: const credentialType = ...; (facoltativa)
      clientPort: clientPort                 // Es: const clientPort = ...;
    };
    this.registrationManager.pendingVCRequests.push({
      request
    });

    res.status(200).send("✅ Autenticazione riuscita, Dati in arrivo!");
     

  } catch (err) {
    console.error("❌ Errore in /verify-challenge:", err);
    return res.status(500).send("Errore interno.");
  }
});
this.app.get("/challenge/:did", (req, res) => {
  const did = req.params.did;

  if (!did) {
    return res.status(400).send("❌ DID mancante.");
  }

  // Genera una challenge casuale (stringa random)
  const challenge = Math.random().toString(36).substring(2, 15);

  // Salva la challenge in memoria, associata al DID
  
  this.registrationManager.challenges[did] = challenge;

  console.log(`➡️ Challenge generata per DID ${did}: ${challenge}`);

  // Invia la challenge al client
  res.status(200).json({ challenge });
});


this.app.post("/vp-revoke", async (req, res) => {
  try {
    const { revokeRequest, signature, publicKey } = req.body;

    if (!revokeRequest || !signature || !publicKey) {
      return res.status(400).send("❌ Payload incompleto.");
    }

    // ✅ Verifica firma della richiesta di revoca
    const message = JSON.stringify(revokeRequest);
    const encoded = new TextEncoder().encode(message);
    const signatureBytes = new Uint8Array(Buffer.from(signature, "base64"));
    const publicKeyBytes = new Uint8Array(Object.values(publicKey));

    const firmaOk = this.nacl.sign.detached.verify(
      encoded,
      signatureBytes,
      publicKeyBytes
    );

    if (!firmaOk) {
      return res.status(401).send("⛔️ Firma non valida. Revoca rifiutata.");
    }

    const { vpId: targetVpId, revokedAt, holder } = revokeRequest;

    if (!Array.isArray(this.server.verifier_accepted_requests)) {
      this.server.verifier_accepted_requests = [];
      console.warn("⚠️ verifier_accepted_requests inizializzato vuoto.");
    }

    let index = -1;
    let decryptedVP;
    let saveDir;

    for (let i = 0; i < this.server.verifier_accepted_requests.length; i++) {
      const entry = this.server.verifier_accepted_requests[i];
      const vpEncrypted = entry.request;
      saveDir = entry.saveDir;

      const {
        encryptedMessage,
        senderPublicEncryptionKey,
        signature,
        senderPublicSignKey
      } = vpEncrypted;

      if (!encryptedMessage || !senderPublicEncryptionKey) {
        console.warn(`⚠️ VP #${i + 1} mancante di dati essenziali`);
        continue;
      }

      try {
        decryptedVP = await this.registrationManager.decryptVP(
          encryptedMessage,
          this.server.entePrivateCryptoKey,
          senderPublicEncryptionKey
        );
      } catch (err) {
        console.error(`❌ Errore decriptando VP #${i + 1}: ${err.message}`);
        continue;
      }

      const isValidVP = await this.registrationManager.verifyVP(
        decryptedVP,
        this.server,
        signature,
        senderPublicSignKey
      );

      if (!isValidVP) {
        console.warn(`❌ Firma non valida per VP #${i + 1}, salto...`);
        continue;
      }

      const vpId = decryptedVP.vpId;
      console.log(`🔍 Confronto VPID ricevuto: ${targetVpId} con VPID in lista: ${vpId}`);

      if (vpId === targetVpId) {
        index = i;
        break;
      }
    }

    if (index === -1) {
      return res.status(404).send(`❌ Nessuna VP trovata con ID ${targetVpId}`);
    }

    // 🧹 Elimina eventuali file embedded salvati
    const files = (decryptedVP.embeddedFiles || []).map(f => f.fileName);
    if (Array.isArray(files) && saveDir) {
      for (const fileName of files) {
        const fullPath = path.join(saveDir, fileName);
        if (fs.existsSync(fullPath)) {
          try {
            fs.unlinkSync(fullPath);
            console.log(`🗑️ File rimosso: ${fullPath}`);
          } catch (err) {
            console.warn(`⚠️ Impossibile rimuovere ${fileName}: ${err.message}`);
          }
        }
      }
    }

    // 🗑️ Rimuovi la VP
    this.server.verifier_accepted_requests.splice(index, 1);
    console.log(`🛑 VP con ID ${targetVpId} revocata da ${holder} alle ${revokedAt}`);

    return res.status(200).send("✅ Revoca registrata, VP e file rimossi.");
  } catch (err) {
    console.error("❌ Errore in /vp-revoke:", err);
    return res.status(500).send("Errore interno.");
  }
});







function decryptVPFromRequest(request, verifierPrivateKeyHex) {
  const { encryptedMessage, senderPublicEncryptionKey } = request;

  if (!encryptedMessage || !senderPublicEncryptionKey) {
    throw new Error("❌ Dati mancanti per la decifratura.");
  }

  // Converti i dati nei formati corretti
  const nonce = naclUtil.decodeBase64(encryptedMessage.nonce);
  const ciphertext = naclUtil.decodeBase64(encryptedMessage.ciphertext);
  const senderPublicKeyBytes = new Uint8Array(Buffer.from(senderPublicEncryptionKey, 'hex'));
  console.log("Chiave privata (hex):", verifierPrivateKeyHex);
  console.log("Lunghezza:", verifierPrivateKeyHex.length); // deve essere 64

  const verifierPrivateKeyBytes = Uint8Array.from(Buffer.from(verifierPrivateKeyHex, 'base64'));

  // Decifra il messaggio
  const decryptedBytes = nacl.box.open(ciphertext, nonce, senderPublicKeyBytes, verifierPrivateKeyBytes);

  if (!decryptedBytes) {
    throw new Error("❌ Decifratura fallita: messaggio non valido o chiavi errate.");
  }

  const vpJsonString = new TextDecoder().decode(decryptedBytes);
  const vp = JSON.parse(vpJsonString);

  return vp;
}

    this.app.post('/receive-message', async (req, res) => {
      try {

        const { encryptedMessage, signature, senderDID, didDocument,clientPort ,clientUs} = req.body;

        if (!encryptedMessage || !senderDID || !signature || !didDocument||!clientPort || !clientUs) {
          return res.status(400).json({ error: "❌ Dati mancanti nella richiesta!" });
        }
        /*console.log("📦 Dati ricevuti dal client:");
        console.log({
          encryptedMessage,
          signature,
          senderDID,
          didDocument,
          clientPort
        });*/


        // 📌 Passiamo i dati a `RegistrationManager`
        const success = this.registrationManager.receiveRegistrationRequest({ encryptedMessage, signature, senderDID, didDocument, clientPort ,clientUs});

        if (success) {
          console.log(`✅ Registrazione ricevuta da: ${senderDID}`);
          return res.json({ message: "✅ Richiesta di registrazione ricevuta!" });
        } else {
          return res.status(500).json({ error: "❌ Errore nella registrazione!" });
        }

      } catch (error) {
        console.error("❌ Errore interno del server:", error);
        return res.status(500).json({ error: "❌ Errore interno del server!" });
      }
    });

    this.app.post("/receive-vp", (req, res) => {
      let saveDir =null;
      try {
        const request = req.body;
        const resolverUrl = "http://localhost:4000";
        console.log("📨 Richiesta di Verifiable Presentation ricevuta!");
        //console.log("📦 Payload ricevuto:", req.body);
        
        const vp = decryptVPFromRequest(request, this.server.entePrivateCryptoKey);
        console.log("🔍 Contenuto VP decifrata:");
        console.log(JSON.stringify(vp, null, 2));

        console.log("📌 controller:", this.server.controller);
        console.log("📌 senderDID:", request.senderDID);
        if (Array.isArray(vp.embeddedFiles) && vp.embeddedFiles.length > 0) {
        saveDir = path.join(
          __dirname,
          'VerifierFiles',
          this.server.controller,
          request.controller
        );
        if (!fs.existsSync(saveDir)) {
          fs.mkdirSync(saveDir, { recursive: true });
        }

        for (const file of vp.embeddedFiles) {
          const { fileName, base64Content } = file; // CAMBIO QUI

          if (!fileName || !base64Content) {
            console.warn("⚠️ File incompleto, ignorato.");
            continue;
          }

          const buffer = Buffer.from(base64Content, 'base64'); // CAMBIO QUI
          const savePath = path.join(saveDir, fileName);
          fs.writeFileSync(savePath, buffer);
          console.log(`✅ Salvato file: ${fileName}`);
        }

      }
      // ✅ Aggiungiamo la richiesta all’array corretto del RegistrationManager
        this.server.verifier_accepted_requests.push({request,saveDir});
        //console.log("Questa è la signature che ricevo: ",request.signature);
        //console.log(JSON.stringify(request, null, 2));

        res.status(200).send("Richiesta VP memorizzata correttamente.");
        return this.startMenu(server.issuerDid,server.controller,server.serverPort);
        
      } catch (err) {
        console.error("❌ Errore durante la memorizzazione della richiesta:", err.message);
        res.status(500).send("Errore interno del server.");
      }
    });
    /*this.app.post('/vp-response', async (req, res) => {
  try {
    const { encryptedVP, nonce, senderPublicKey } = req.body;

    if (!encryptedVP || !nonce || !senderPublicKey) {
      return res.status(400).json({ error: "Dati mancanti nel payload" });
    }

    // Verifica che la struttura lato server sia pronta
    if (!server.verifier_accepted_request) {
      server.verifier_accepted_request = [];
    }

    // Salva la richiesta cifrata nel buffer
    this.server.verifier_accepted_requests.push({
      encryptedVP,
      nonce,
      senderPublicKey,
      receivedAt: new Date().toISOString()
    });

    console.log("📥 VP cifrata salvata in memoria (non decifrata).");

    res.json({ message: "VP ricevuta e salvata (ancora cifrata)" });
  } catch (err) {
    console.error("❌ Errore in /vp-response:", err.message);
    res.status(500).json({ error: "Errore interno lato verifier" });
  }
});*/



  }
async mostraRichiestePendenti(rl) {
  if (!this.registrationManager.pendingVCRequests || this.registrationManager.pendingVCRequests.length === 0) {
    console.log("🎉 Nessuna richiesta in attesa.");
    return { status: "empty", message: "Nessuna richiesta da elaborare." };
  }

  console.log("📋 Richieste in attesa di invio:\n");
  this.registrationManager.pendingVCRequests.forEach((job, index) => {
    const { senderDID, client_username } = job.request;
    console.log(`${index + 1}. DID: ${senderDID}, client: ${client_username}`);
  });

  // Prompt: seleziona numero richiesta
  const scelta = await new Promise(resolve => {
    rl.question("➡️ Seleziona il numero da inviare oppure 0 per annullare: ", resolve);
  });

  const idx = parseInt(scelta, 10) - 1;

  if (idx < 0 || idx >= this.registrationManager.pendingVCRequests.length) {
    return { status: "cancelled", message: "Invio annullato." };
  }

  // Prompt: tipo di credenziale
  const credentialType = await new Promise(resolve => {
    rl.question("📝 Inserisci il tipo di VC da inviare (es. Referto, Immagini, Ricetta): ", resolve);
  });

  // Salva il tipo nella richiesta
  this.registrationManager.pendingVCRequests[idx].request.credentialType = credentialType.trim() || "RegistrazioneGenerica";

  const { request } = this.registrationManager.pendingVCRequests.splice(idx, 1)[0];
  const parentFolder = this.server.issuerFilesPath;
  const enteKeys = {
    issuerDid: this.server.issuerDid,
    publicSignKey: this.server.entePublicSignKey,
    privateSignKey: this.server.entePrivateSignKey,
    publicCryptoKey: this.server.entePublicCryptoKey,
    privateCryptoKey: this.server.entePrivateCryptoKey
  };

  try {
    await this.registrationManager.sendDataToClient(request, enteKeys, parentFolder,credentialType);
    console.log("✅ Richiesta inviata correttamente.");
    return { status: "success", message: "VC inviata con successo." };
  } catch (e) {
    console.error("❌ Errore durante l’invio:", e.message);
    return { status: "error", message: e.message };
  }
}




 async startMenu(issuerDid = '❌ Unset', controller = '❌ Unset', serverPort = '❌ Unset') {
    console.log(`
  🧾  DID Server:             ${issuerDid}
  🎩  Controller del server:  ${controller}
  📡  Porta in ascolto:       ${serverPort}
  `);
    console.log("\n🚀 SERVER MENU");

    // ⚙️ Server Utility
    console.log("\n🧰 Server Utility:");
    console.log("1. Avvia server");
    console.log("4. Esci");

    // 🔐 Funzioni Issuer
    console.log("\n🏛️ Funzioni Issuer:");
    console.log("2. Visualizza richieste di VC");
    console.log("3. Visualizza richieste di registrazione");

    // 🕵️ Funzioni Verifier
    console.log("\n🕵️ Funzioni Verifier:");
    console.log("5. Invia richiesta di VP a un client");
    console.log("6. Visualizza VP ricevute dai client");
    console.log("7. Visualizza Richieste di Revoca");



    this.rl.question("\nSeleziona un'opzione: ", async (option) => {
      switch (option.trim()) {
        case "1":
          this.rl.question('🔹 Inserisci DID ente: ', async (enteDid) => {
          this.rl.question('💳 Inserisci controller: ', async (controller) => {
            this.rl.question('🧾 Inserisci codice fiscale ente: ', async (fiscalCode) => {
              await this.server.startServer(enteDid, controller, fiscalCode);
              await this.startMenu(this.server.issuerDid,this.server.controller,this.server.serverPort);
            });
          });
        });

          break;

        case "2":
          try {
            const result = await this.mostraRichiestePendenti(this.rl);
            if (result.status === "success") {
                  
              console.log("Dati inviati con successo");
              await this.startMenu(this.server.issuerDid,this.server.controller,this.server.serverPort);
              // tutto okay
            } else if (result.status === "error") {
              console.log("Problema nell'invio");
              await this.startMenu(this.server.issuerDid,this.server.controller,this.server.serverPort);
            }
            } catch (err) {
              console.error("🔥 Errore imprevisto:", err.message);
            }

          break;

        case "3":
          console.log("🔎 Visualizzo le richieste...");
          const requests = await this.registrationManager.viewRegistrations();

          if (requests.length === 0) {
            console.log("✅ Nessuna richiesta di registrazione.");
            this.startMenu(this.server.issuerDid,this.server.controller,this.server.serverPort);
          } else {
            requests.forEach(req => {
              console.log(`🔢 ${req.number} - DID: ${req.senderDID}`);
              console.log(`   📅 Data: ${req.timestamp}`);
              console.log(`   💬 Messaggio: ${req.decryptedMessage}`);
              console.log(`   🖊️ Firma: ${req.signatureValid}`);
              console.log(`   🖊️ Porta Client: ${req.ClientPort}`);
              console.log(`   🖊️ Codice Fiscale: ${req.codice_fiscale}`);
              console.log("--------------------------------------------------");
            });

            this.rl.question("🆔 Inserisci il numero della richiesta da gestire: ", (requestNumber) => {
              this.rl.question("✔ Vuoi accettarla ('accept') o rifiutarla ('reject')? ", (action) => {

                const req = requests[requestNumber - 1];
                let clientCont = req?.clientUs || null; // fallback difensivo
                if (req && req.codice_fiscale) {
                  this.registrationManager.registrationRequests[requestNumber - 1].codice_fiscale = req.codice_fiscale;
                } else {
                  console.warn("⚠️ Codice fiscale mancante o richiesta non trovata.");
                }

                if (action === 'accept') {
                  this.rl.question("📦 Inserisci il tipo di credenziale da emettere (es. RefertoMedico, TAC, Immagini): ", (credentialType) => {
                    this.registrationManager.acceptOrRejectRequest(Number(requestNumber), action, {
                      issuerDid: this.server.issuerDid,
                      privateCryptoKey: this.server.getPrivateCryptoKey(),
                      publicCryptoKey: this.server.getPublicCryptoKey(),
                      privateSignKey: this.server.getPrivateSignKey(),
                      publicSignKey: this.server.getPublicSignKey(),
                      clientPort: this.server.serverPort,
                      credentialType: credentialType.trim() || "RegistrazioneGenerica"
                    })
                    .then((result) => {
                      if (result?.status === 'ok') {
                        console.log(`✅ Richiesta gestita con successo: ${result.codiceFiscale}`);
                      } else if (result?.status === 'duplicate') {
                        console.warn(`⚠️ Registrazione accettata, ma CF già presente: ${result.codiceFiscale}`);
                      } else if (result?.status === 'rejected') {
                        console.log(`🛑 Richiesta ${requestNumber} rifiutata.`);
                      } else {
                        console.warn(`⚠️ Esito imprevisto:`, result?.message || result);
                      }

                      this.server.createFolderForClient(clientCont, this.server.issuerFilesPath);
                      this.startMenu(this.server.issuerDid, this.server.controller, this.server.serverPort);
                    })
                    .catch(err => {
                      console.error("❌ Errore nella gestione della richiesta:", err.message);
                      this.startMenu(this.server.issuerDid, this.server.controller, this.server.serverPort);
                    });

                  });
                } else {
                  this.registrationManager.acceptOrRejectRequest(Number(requestNumber), action, {
                    issuerDid: this.server.issuerDid,
                    privateCryptoKey: this.server.getPrivateCryptoKey(),
                    publicCryptoKey: this.server.getPublicCryptoKey(),
                    privateSignKey: this.server.getPrivateSignKey(),
                    publicSignKey: this.server.getPublicSignKey(),
                    clientPort: this.server.serverPort
                  })
                  .then(() => this.startMenu(this.server.issuerDid,this.server.controller,this.server.serverPort))
                  .catch(err => {
                    console.error("❌ Errore nella gestione della richiesta:", err);
                    this.startMenu(this.server.issuerDid,this.server.controller,this.server.serverPort);
                  });
                }
              });
            });
          }

          break;


        case "4":
          console.log("👋 Uscita dal menu.");
          this.rl.close();
          return;
        case '5':
        await this.registrationManager.verifierRequest(this.server);
        await this.startMenu(this.server.issuerDid,this.server.controller,this.server.serverPort);
        break;

      case '6':
        await this.registrationManager.showReceivedVPs(this.rl,this.server,this.server.entePrivateCryptoKey);
         await this.startMenu(this.server.issuerDid,this.server.controller,this.server.serverPort);
        break;
        case '7':
          const revoche = this.registrationManager.revokeRequests || [];

          if (revoche.length === 0) {
            console.log("📭 Nessuna richiesta di revoca ricevuta.");
              await this.startMenu(this.server.issuerDid,this.server.controller,this.server.serverPort);
          }

          console.log("📋 Richieste di revoca ricevute:");
          revoche.forEach((req, i) => {
            console.log(`${i + 1}) VP ID: ${req.vpId} | Holder: ${req.holder} | Data: ${req.revokedAt}`);
          });

          this.rl.question("✏️ Inserisci il numero della richiesta da accettare (o premi invio per annullare): ", async (input) => {
            const index = parseInt(input) - 1;

            if (isNaN(index) || index < 0 || index >= revoche.length) {
              console.log("🔹 Nessuna richiesta accettata.");
              return;
            }

            const accettata = revoche.splice(index, 1)[0]; // rimuovi la revoca dall’elenco
            const vpIdToRemove = accettata.vpId;

            // 🔍 Rimuovi la VP corrispondente da verifier_accepted_requests
            const originalList = registrationManager.verifier_accepted_requests || [];
            const originalLength = originalList.length;

            registrationManager.verifier_accepted_requests = originalList.filter((vp) => {
              const serializedVP = JSON.stringify(vp);
              const hash = crypto.createHash("sha256").update(serializedVP).digest("hex");
              return hash !== vpIdToRemove;
            });

            if (registrationManager.verifier_accepted_requests.length < originalLength) {
              console.log(`✅ VP con ID ${vpIdToRemove} rimossa con successo da verifier_accepted_requests.`);
            } else {
              console.log(`⚠️ Nessuna VP corrispondente trovata con ID ${vpIdToRemove}.`);
            }

            console.log(`📬 Richiesta di revoca accettata da ${accettata.holder}.`);
          });

          break;



        default:
          console.log("⚠️ Opzione non valida!");
          this.startMenu(this.server.issuerDid,this.server.controller,this.server.serverPort);
      }
    });
  }

  startServer() {
    this.app.listen(this.server.serverPort, () => {
      console.log(`✅ Server API avviato su http://localhost:${this.server.serverPort}`);

    });
  }
}

// 🔹 Avvio automatico del menu e del server API
const serverManager = new ServerManager();
serverManager.startMenu();
