import readline from 'readline';
import fetch from 'node-fetch';
import { startServer , viewRegistrations,acceptOrRejectRequest} from './server_v4.js';
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

export function serverMenu() {
  console.log("\n🚀 SERVER MENU:");
  console.log("1. Avvia server");
  console.log("2. Ferma server");
  console.log("3. Visualizza richieste di registrazione");
  console.log("4. Esci");

  rl.question("\nSeleziona un'opzione: ", async (option) => {
    switch (option.trim()) {
      case "1":
        rl.question('🔹 Inserisci DID ente: ', async (enteDid) => {
                rl.question('💳 Inserisci controller ', async (controller) => {
                  
                  await startServer(enteDid,controller);
                  
                  
                });
              });
              break;
      case "2":
        console.log("Stop");
        await fetch('http://localhost:3000/stop-server', { method: 'POST' });
        break;
      case "3":
          console.log("🔎 Visualizzo le richieste...");
          const requests = await viewRegistrations();
          requests.forEach(req => {
            console.log(`🔢 ${req.number} - DID: ${req.senderDID} | Data: ${req.timestamp} | Messaggio: ${req.decryptedMessage} | Firma: ${req.signatureValid}`);
          });

          rl.question("🆔 Inserisci il numero della richiesta da gestire: ", (requestNumber) => {
            rl.question("✔ Vuoi accettarla ('accept') o rifiutarla ('reject')? ", (action) => {
              acceptOrRejectRequest(Number(requestNumber), action);
              serverMenu(); // 🔄 Torna al menu
            });
          });
          break;
      case "4":
        console.log("👋 Uscita dal menu.");
        rl.close();
        return;
      default:
        console.log("⚠️ Opzione non valida!");
    }

    serverMenu(); // Riproponi il menu dopo ogni scelta
  });
}

serverMenu();
