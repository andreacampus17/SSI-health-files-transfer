import express from "express";
const app = express();
app.use(express.json());
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs'; 
import { ClientSetup } from './clientUtils.js';
import { ClientCommunication } from './ClientCommunication.js';
import readline from 'readline';
import multer from 'multer';

const resolverUrl = "http://localhost:4000";
const upload = multer({ dest: 'uploads/' });
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class ClientMain {
  constructor() {
    this.app = express();
    this.app.use(express.json()); // ✅ middleware JSON applicato all'istanza corretta
    this.rl = readline.createInterface({ input: process.stdin, output: process.stdout });

    this.clientSetup = new ClientSetup(this.rl);  // 🔹 Passiamo readline al setup!
    this.clientCommunication = new ClientCommunication(this.clientSetup,this.rl);
    registerClientEndpoints(this.app, this.clientCommunication,this.clientSetup,this.rl,this); // 🧩 Qui la agganci elegantemente
  }

  async startClientServer() {
    await this.clientSetup.initialize();

    console.log(`🟢 Client in ascolto sulla porta ${this.clientSetup.clientPort}...`);

    this.app.listen(this.clientSetup.clientPort, () => {
      console.log(`🚀 Server client avviato sulla porta ${this.clientSetup.clientPort} e pronto a comunicare con il server sulla porta ${this.clientSetup.serverPort}`);
    });

    // 🔹 Aspettiamo finché `this.clientSetup.identity` non è definito
    while (!this.clientSetup.identity) {
        console.log("⏳ In attesa dell'identità...");
        await new Promise(resolve => setTimeout(resolve, 1000)); // 🔹 Controlliamo ogni mezzo secondo
    }
    this.clientSetup.clientFilesPath=this.clientSetup.createClientFilesFolder(this.clientSetup.controller);
    console.log("✅ Identità trovata! Avvio del menu...");
    await clientMenu(this.clientSetup, this.rl, this);

   }
async  handleChoice(choice,rl) {
    switch (choice) {
      case '1': {
        const enteDid = await askUser(rl,'🔹 Inserisci DID ente: ');
        const userData = await askUser(rl, '💳 Inserisci Verifiable Credential (VC): ');

        const fiscalCode = await askUser(rl, '💳 Inserisci il codice fiscale: ');
        const vcPayload = await buildMinimalVC(userData, fiscalCode);

        console.log("👤 DID del client usato:", this.clientSetup.identity.did);
        if (!this.clientSetup?.identity?.did) {
          console.error("❌ Errore: DID non definito!");
          return;
        }

        if (!vcPayload) {
          console.error("❌ Errore: dati mancanti per la firma!");
          return;
        }
        const vcString = JSON.stringify(vcPayload);
        //console.log("🧱 Oggetto VC generato dopo la serializzazione:", vcString);

        await this.clientCommunication.encryptAndSendMessage(this.clientSetup.controller,
          this.clientSetup.identity.did,
          this.clientSetup.identity.didDocument,
          vcString,
          enteDid,
          this.clientSetup.clientPrivateCryptoKey,
          this.clientSetup.clientPublicCryptoKey,
          this.clientSetup.clientPrivateSignKey,
          this.clientSetup.clientPublicSignKey,
          resolverUrl,
          this.clientSetup.clientPort
        );
        await clientMenu(this.clientSetup, this.rl, this);
        break;
      }
      case '2': {
        let serverP=this.clientSetup.serverPort;
        const serverUrl=`http://localhost:${serverP}`;
        const dati = await this.clientCommunication.dataRequest(serverUrl,this.clientSetup.identity.did);
        const new_serverUrl=`http://localhost:${serverP}`;
        await this.clientCommunication.verifyChallenge(this.clientSetup.clientPort,this.clientSetup.identity.did,this.clientSetup.identity.didDocument, dati, this.clientSetup.clientPrivateSignKey, new_serverUrl,this.clientSetup.controller);
        break;
      }
      case '3':
        await this.clientSetup.viewAcceptedRegistrationRequest();
        break;
      case '4':
        console.log("📜 Visualizzazione delle VC accettate...");
        await this.clientSetup.viewAcceptedVCs(this.rl);
        break;
        case '5':
        console.log("📜 Visualizzazione delle VC accettate...");
        await this.clientSetup.changeServerPort();
        break;
        case '6':
        console.log("📜 Visualizzazione delle richieste da Verifier");
          const result = await this.clientSetup.handleVerifierRequests();

        if (result && result.accepted) {
        try {
          const { selectedRequest, index, verifierDID, requestedType } = result;

          const verifierPublicCryptoKey = await this.clientCommunication.getPublicKeyByDID(
            verifierDID,
            'http://localhost:4000'
          );
          const filesFolderPath = path.join(__dirname, 'ClientFiles', this.clientSetup.controller);
          const { signedVP, signature } = await this.clientCommunication.createAndSignVP(
            selectedRequest,
            requestedType,
            verifierPublicCryptoKey,
            this.clientSetup,
            filesFolderPath
          );

          const verifierPort = selectedRequest.payload.verifierPort;

          await this.clientCommunication.sendVPtoVerifier(
            this.clientSetup,
            signature,
            verifierPort,
            signedVP,
            verifierPublicCryptoKey,
            this.clientSetup.clientPrivateCryptoKey,
            this.clientSetup.clientPublicCryptoKey
          );

          console.log("✅ VP inviata con successo!");

          this.clientSetup.authorizedPresentations.push({
            verifierDID,
            requestedType,
            sentAt: new Date().toISOString(),
            signedVP,
            verifierPort
          });

          this.clientSetup.verifierRequests.splice(index, 1);
        } catch (err) {
          console.error("❌ Errore durante creazione o invio VP:", err.message);
          console.error("📚 Stacktrace completo:\n", err.stack);
  }
} else {
  console.log("🔙 Nessuna richiesta accettata o risultato assente. Torno al menu...");
  await clientMenu(this.clientSetup, this.rl, this);
}
        break;
        case '7': {
        const presentations = this.clientSetup.authorizedPresentations || [];

        if (presentations.length === 0) {
          console.log("📭 Nessuna VP autorizzata finora.");
          return await clientMenu(this.clientSetup, this.rl, this);
        }

        console.log("📋 VP autorizzate:");
        presentations.forEach((entry, i) => {
          console.log(`${i + 1}) ➡️ Verifier: ${entry.verifierDID} | Tipo VC: ${entry.requestedType} | Data: ${entry.sentAt} | Porta Verifier: ${entry.verifierPort}`);
        });

        // 🔁 Attendi input utente in modo corretto
        const input = await new Promise((resolve) => {
          this.rl.question("✏️ Inserisci il numero della VP da revocare (o premi invio per annullare): ", resolve);
        });

        const index = parseInt(input) - 1;
        const vp = this.clientSetup.authorizedPresentations[index]?.signedVP;


        if (isNaN(index) || index < 0 || index >= presentations.length) {
          console.log("🔹 Nessuna revoca eseguita.");
          return await clientMenu(this.clientSetup, this.rl, this);
        }

        try {
          await this.clientCommunication.revocaPresentazione(index, this.clientSetup,vp.vpId);
        } catch (err) {
          console.error("❌ Errore durante la revoca della presentazione:", err.message);
           await this.clientCommunication.revocaPresentazione(index, this.clientSetup);
        }

        return await clientMenu(this.clientSetup, this.rl, this); // Torna al menu una sola volta
      }



      default:
        console.log("❌ Scelta non valida.");
    }

    clientMenu(this.clientSetup, rl, clientInstance);
}  

}

async function buildMinimalVC(userData, fiscalCode) {
  console.log("📦 userData ricevuto:", userData);
  console.log("📦 fiscalCode ricevuto:", fiscalCode);

  return {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiableCredential"],
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      ...(typeof userData === 'string' ? { message: userData } : userData),
      fiscal_code: fiscalCode
    }
  };
}


async function clientMenu(clientSetup, rl, clientInstance) {  
  console.log("\n👤 DID attuale del client:", clientSetup.identity.did);
  console.log(`
🧠  Controller attivo:        ${clientSetup.controller}
📡  Porta server Issuer:      ${clientSetup.serverPort}
`);

    rl.question(
    `🔸 Menu Client
    1️⃣ Invia richiesta di registrazione
    2️⃣ Richiedi dati
    3️⃣ Visualizza risposta alla richiesta di registrazione
    4️⃣ Visualizza dati verificati
    5️⃣ Cambia server
    6️⃣ Visualizza richieste VP da verifier
    7️⃣ Visualizza autorizzazioni concesse

    `,
      async (choice) => {
        await clientInstance.handleChoice(choice, rl); // 🔹 Ora usiamo l'istanza corretta
      }
    );

}


async function askUser(rl, question) {
  return new Promise((resolve) => {
    if (!rl) {  // 🔹 Controlliamo che `rl` sia valido
      console.error("❌ Errore: readline non inizializzato!");
      return resolve(null);
    }

    rl.question(question, (answer) => {
      resolve(answer.trim());  // 🔹 Puliamo l'input
    });
  });
}


function registerClientEndpoints(app, clientCommunication, clientSetup,rl,clientMain) {
  app.post("/receive-server-vc", (req, res) => {
    console.log("📨 VC ricevuta!");
    //console.log("📦 Contenuto della richiesta ricevuta:");
    //console.log(JSON.stringify(req.body, null, 2));
    //console.log("📥 Ricevuti allegati:", req.files);


    try {
      clientCommunication.processReceivedRegistrationResponse(req.body, res, clientSetup.clientPrivateCryptoKey,clientSetup);
      return clientMenu(clientSetup,rl,clientMain);
      //await clientMenu(this.clientSetup.identity, this.rl, this);
    } catch (error) {
      console.error("❌ Errore nel salvataggio della VC:", error.stack || error.message);
      res.status(500).json({ error: "❌ Errore interno del server!" });
    }
  });
  app.post("/verifier-request", (req, res) => {
  console.log("📩 Richiesta da verifier ricevuta:");
  //console.log(JSON.stringify(req.body, null, 2));

  try {
    clientSetup.verifierRequests.push(req.body); // salva la richiesta
    res.status(200).json({ status: "richiesta salvata" });
    return clientMenu(clientSetup,rl,clientMain);
  } catch (error) {
    console.error("❌ Errore nel salvataggio della richiesta verifier:", error.stack || error.message);
    res.status(500).json({ error: "❌ Errore interno del server!" });
    return clientMenu(clientSetup,rl,clientMain);
  }
});
app.post('/receive-server-data', upload.array('allegati'), (req, res) => {
  try {
    console.log("📨 VC ricevuta!");
    console.log("📥 Allegati temporanei ricevuti:", req.files.map(f => f.originalname));

    // ✅ Parsing VC (è una stringa JSON nel form-data)
    const vc = JSON.parse(req.body.vc);
    console.log("📜 Contenuto VC:", vc);

    // 📂 Costruzione del percorso di destinazione finale
    const baseDir = path.join(__dirname, '..', 'ClientFiles');
    const controllerName = clientSetup.controller; // preso dal setup
   const finalFolder = path.join(__dirname, 'ClientFiles', controllerName);


    fs.mkdirSync(finalFolder, { recursive: true });

    // 📦 Spostamento degli allegati nella cartella finale
    req.files.forEach(file => {
      const sourcePath = file.path; // es: uploads/xyz123
      const targetPath = path.join(finalFolder, file.originalname);
      fs.renameSync(sourcePath, targetPath);
      console.log("📥 Salvato:", targetPath);
    });

    // 🔐 Elaborazione della VC ricevuta
    clientCommunication.processReceivedVC(vc, res, clientSetup.clientPrivateCryptoKey, clientSetup,finalFolder);

    // 📲 Torna al menu principale del client
    return clientMenu(clientSetup, rl, clientMain);

  } catch (e) {
    console.error("❌ Errore nella gestione della VC:", e.stack || e.message);
    res.status(500).json({ error: "Errore lato client" });
  }
});

  app.post("/verifier-request", (req, res) => {
  console.log("📩 Richiesta da verifier ricevuta:");
  console.log(JSON.stringify(req.body, null, 2));

  try {
    clientSetup.verifierRequests.push(req.body); // salva la richiesta
    res.status(200).json({ status: "richiesta salvata" });
    return clientMenu(clientSetup,rl,clientMain);
  } catch (error) {
    console.error("❌ Errore nel salvataggio della richiesta verifier:", error.stack || error.message);
    res.status(500).json({ error: "❌ Errore interno del server!" });
    return clientMenu(clientSetup,rl,clientMain);
  }
});
}




const clientInstance = new ClientMain();
clientInstance.startClientServer();
