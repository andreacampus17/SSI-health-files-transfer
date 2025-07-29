import { exec } from 'child_process';
import { showMenu } from './client_v4.js'; // 🔹 Ora `client_v4.js` gestisce il menu

function runSystem(name, command) {
  exec(`gnome-terminal -- bash -c "${command}; exec bash"`, (err) => {
    if (err) {
      console.error(`❌ Errore nell'avvio di ${name}:`, err.message);
    } else {
      //console.log(`🚀 ${name} avviato in un nuovo terminale!`);
    }
  });
}

// 🔹 Avvia issuer e resolver in terminali separati
runSystem('Issuer', 'node serverMenu.js');
runSystem('Resolver', 'node resolver_v4.js');

// 🔹 Esegui il client nel terminale attuale
//console.log('🚀 Avvio del client nel terminale attuale...');
