# Progetto DID e Credenziali Verificabili

Un ecosistema completo per la gestione di Identificatori Decentralizzati (DID) e Credenziali Verificabili (VCs), composto da un **Server Issuer/Verifier**, un **Client Holder** e un **Resolver DID**. Il sistema è progettato per dimostrare un flusso end-to-end di autenticazione decentralizzata, emissione, presentazione e revoca di credenziali, con un forte focus sulla sicurezza crittografica e la persistenza dei dati.

## Architettura del Progetto

Il progetto è suddiviso in tre componenti principali che interagiscono tra loro:

1.  **Server (Issuer/Verifier):** Un'applicazione Node.js con interfaccia a riga di comando (CLI) e API RESTful. Agisce sia come emittente di Credenziali Verificabili che come verificatore di Verifiable Presentations.

2.  **Client (Holder):** Un'applicazione Node.js con interfaccia a riga di comando (CLI) che rappresenta il "detentore" delle credenziali. Permette di richiedere, ricevere, gestire e presentare Credenziali Verificabili.

3.  **Resolver DID:** Un servizio Node.js indipendente che funge da registro per i DID e le chiavi pubbliche associate, persistendo i dati in un database PostgreSQL. È essenziale per la risoluzione dei DID all'interno dell'ecosistema.

## Caratteristiche Principali

### Server (Issuer/Verifier)

* **Autenticazione Decentralizzata (DID-based):** Gestione di challenge criptografiche e verifica delle firme per l'autenticazione sicura dei client.

* **Emissione di Credenziali Verificabili (Issuer):** Accetta richieste di registrazione e emette VCs personalizzate (es. Referti, Immagini).

* **Verifica di Verifiable Presentations (Verifier):** Riceve, decifra, verifica e memorizza VPs, inclusi file embedded.

* **Gestione Revoche:** Supporto per la richiesta e l'elaborazione di revoche di VPs.

* **Interfaccia CLI:** Menu interattivo per il controllo delle operazioni del server.

* **Crittografia:** Utilizzo estensivo di `tweetnacl` per operazioni crittografiche robuste.

### Client (Holder)

* **Gestione Identità Decentralizzata:** Creazione e gestione del proprio DID e delle chiavi crittografiche.

* **Richiesta e Ricezione VCs:** Invia richieste di registrazione al server e riceve Credenziali Verificabili.

* **Presentazione VPs:** Crea e invia Verifiable Presentations al server Verifier in risposta a richieste specifiche.

* **Revoca VPs:** Possibilità di revocare presentazioni precedentemente autorizzate.

* **Interfaccia CLI:** Menu interattivo per le operazioni del client.

### Resolver DID

* **Registro DID Centralizzato:** Memorizza i DID e le chiavi pubbliche di cifratura e firma per Issuer e Client.

* **Risoluzione Chiavi Pubbliche:** Fornisce endpoint per recuperare chiavi pubbliche di cifratura e firma dato un DID o un codice fiscale.

* **Registrazione Entità:** Permette a Issuer e Client di registrarsi nel sistema del resolver.

* **Persistenza Dati:** Utilizza PostgreSQL per l'archiviazione sicura dei dati dei DID.

## Tecnologie Utilizzate

* **Node.js** (con moduli ES - `"type": "module"`)

* **Express.js** (Framework Web per Server e Resolver)

* **Veramo Framework:** Per la gestione di DID e VCs (principalmente nel Server e Client).

* **PostgreSQL:** Database relazionale per il Resolver.

* **Nacl (Networking and Cryptography library):** Tramite `tweetnacl` e `tweetnacl-util` per tutte le operazioni crittografiche.

* **readline:** Per le interfacce a riga di comando di Server e Client.

* **express-session:** Per la gestione delle sessioni (nel Server).

* **multer:** Per la gestione degli upload di file (nel Client).

* **fs** e **path:** Per operazioni sul file system.

* **node-fetch** e **axios:** Per richieste HTTP.

## Installazione

Per avviare l'intero ecosistema in locale, segui questi passaggi:

1.  **Clona il repository:**

    ```bash
    git clone <andreacampus17/SSI-health-files-transfer>
    cd <nodeServer>
    ```

2.  **Configura il Database PostgreSQL:**

    * Assicurati di avere un'istanza di PostgreSQL in esecuzione.

    * Crea un database per il tuo progetto (es. `did_resolver_db`).

    * **Crea la tabella `did_second`** nel tuo database PostgreSQL. La struttura dovrebbe essere simile a:

        ```sql
        CREATE TABLE did_second (
            id SERIAL PRIMARY KEY,
            did VARCHAR(255) UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            role VARCHAR(50) NOT NULL, -- 'issuer' o 'client'
            display_name VARCHAR(255),
            fiscal_code VARCHAR(255) UNIQUE,
            metadata JSONB DEFAULT '{}' -- Per signingKey e altri dati
        );
        ```

    * Nella cartella del **resolver**, crea un file `config.js` (se non esiste) con la configurazione del tuo database:

        ```javascript
        import pg from 'pg';
        const { Pool } = pg;

        const pool = new Pool({
            user: 'your_db_user',
            host: 'localhost',
            database: 'did_resolver_db',
            password: 'your_db_password',
            port: 5432,
        });

        export default pool;
        ```

3.  **Variabili d'Ambiente (Server):**

    * Nella cartella del **server**, crea un file `.env` (o equivalente) per la variabile di sessione:

        ```
        SESSION_SECRET=un_segreto_molto_forte_e_casuale_per_le_sessioni
        ```

4.  **Installazione delle Dipendenze per Ogni Componente:**

    * Naviga nella cartella di ogni componente (`server`, `client`, `resolver`) e installa le dipendenze:

        ```bash
        cd server
        npm install
        cd ../client
        npm install
        cd ../resolver
        npm install
        ```

## Utilizzo

Per avviare l'intero ecosistema, è necessario avviare ciascun componente separatamente nell'ordine corretto:

1.  **Avvia il Resolver DID:**

    * Apri un nuovo terminale.

    * Naviga nella cartella del `resolver`.

    * Esegui:

        ```bash
        node resolver.js
        ```

    * Il resolver sarà operativo su `http://localhost:4000`.

2.  **Avvia il Server (Issuer/Verifier):**

    * Apri un nuovo terminale.

    * Naviga nella cartella del `server`.

    * Esegui:

        ```bash
        node server_v5.js
        ```

    * Verrà mostrato un menu CLI. Seleziona l'opzione "1. Avvia server" e inserisci le informazioni richieste (DID ente, controller, codice fiscale ente). Il server API sarà in ascolto sulla porta configurata (es. 3000).

3.  **Avvia il Client (Holder):**

    * Apri un nuovo terminale.

    * Naviga nella cartella del `client`.

    * Esegui:

        ```bash
        node client_v5.js
        ```

    * Il client si avvierà e presenterà un menu CLI interattivo, permettendoti di interagire con il server (richiedere registrazioni, presentare VPs, ecc.).

### Endpoint API e Flussi di Interazione

#### Resolver DID (`http://localhost:4000`)

* `POST /register-issuer`: Registra un Issuer.

* `POST /register-client`: Registra un Client.

* `GET /resolve/:did`: Risolve un DID e restituisce la chiave pubblica di cifratura.

* `GET /signing-key/:did`: Risolve un DID e restituisce la chiave pubblica di firma.

* `POST /verifier-resolve-request`: Risolve DID e chiavi di un client tramite codice fiscale per i Verifier.

#### Server (Issuer/Verifier - es. `http://localhost:3000`)

* `POST /verify-challenge`: Verifica la challenge di autenticazione del client.

* `GET /challenge/:did`: Genera una challenge per un DID specifico.

* `POST /receive-message`: Riceve richieste di registrazione dal client.

* `POST /receive-vp`: Riceve Verifiable Presentations dal client.

* `POST /vp-revoke`: Gestisce le richieste di revoca di VPs.

#### Client (Holder - es. `http://localhost:3001`)

* `POST /receive-server-vc`: Riceve Credenziali Verificabili dal server Issuer.

* `POST /verifier-request`: Riceve richieste di Verifiable Presentation dal server Verifier.

* `POST /receive-server-data`: Riceve dati e allegati dal server.

## Struttura del Progetto
.
```plaintext
.
├── client/
│   ├── client_v5.js            # Punto di ingresso del client, logica CLI e API
│   ├── clientUtils.js          # Utilità per il setup del client (DID, chiavi, ecc.)
│   ├── ClientCommunication.js  # Logica per la comunicazione HTTP con server e resolver
│   └── ClientFiles/            # Cartella per i file ricevuti dal server (creata dinamicamente)
├── server/
│   ├── server_v5.js            # Punto di ingresso del server, logica CLI e API
│   ├── serverSetup.js          # Utilità per il setup del server (DID, chiavi, Express)
│   ├── registrationManager.js  # Logica per la gestione di registrazioni, VC, VP, revoche
│   └── VerifierFiles/          # Cartella per i file embedded nelle VPs ricevute (creata dinamicamente)
├── resolver/
│   ├── resolver.js             # Punto di ingresso del resolver, API e interazione DB
│   └── config.js               # Configurazione del database PostgreSQL
├── package.json                # Dipendenze e script del progetto
└── .env                        # Variabili d'ambiente (per il server)
## Contribuire

Se desideri contribuire a questo progetto, segui queste linee guida:

1.  Forka il repository.

2.  Crea un nuovo branch (`git checkout -b feature/nome-feature`).

3.  Apporta le tue modifiche.

4.  Esegui i test (`npm test` se ne hai definiti).

5.  Fai il commit delle tue modifiche (`git commit -m 'Aggiunta nuova feature'`).

6.  Effettua il push al branch (`git push origin feature/nome-feature`).

7.  Apri una Pull Request.

## Licenza

Questo progetto è rilasciato sotto licenza [ISC](https://opensource.org/licenses/ISC).