import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
import crypto from 'crypto';
import {getEntePublicCryptoKey,getEntePrivateCryptoKey} from "./server_v4.js"


export async function encryptAndSendToClient(
  issuerName,
  issuerDid,
  clientDID,
  clientPublicCryptoKeyBytes, // ✅ Chiave pubblica generata con NaCl
  issuerPublicSignKeyBytes,
  issuerPrivateSignKeyBytes, // 🔐 Chiave privata dell'ente per firmare
  issuerPrivateCryptoKey,
  issuerPublicCryptoKey,
  responseData,
) {
  try {
    console.log("🚀 Inizio processo - Creazione, firma e crittografia della VC");

    // 📌 Creazione della Verifiable Credential (VC)
    const vcPayload = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "type": ["VerifiableCredential"],
      "issuer": issuerDid,
      "issuanceDate": new Date().toISOString(),
      "credentialSubject": {
        "id": clientDID,
        ...responseData, // ✅ Inseriamo i dati dinamici
      },
    };

    console.log("🔎 VC generata:", JSON.stringify(vcPayload, null, 2));

    // 🔹 Firma della VC con la chiave privata dell'ente
    const vcString = JSON.stringify(vcPayload);
    const vcBytes = naclUtil.decodeUTF8(vcString);
    const signatureBytes = nacl.sign.detached(vcBytes, issuerPrivateSignKeyBytes);
    const signatureBase64 = naclUtil.encodeBase64(signatureBytes);

    const signedVC = { ...vcPayload, signature: signatureBase64 ,issuerPublicSignKey: naclUtil.encodeBase64(issuerPublicSignKeyBytes)};
    console.log("✅ VC firmata:", JSON.stringify(signedVC, null, 2));
    console.log("Questo è issuer did:",issuerDid);
    // 🔹 Crittografia della VC con la chiave pubblica del client e la privata dell'ente
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const encryptedMessageBytes = nacl.box(
      naclUtil.decodeUTF8(JSON.stringify(signedVC)), // ✅ Convertiamo la VC firmata in bytes
      nonce,
      clientPublicCryptoKeyBytes, // ✅ Chiave pubblica del client (CORRETTA!)
      issuerPrivateCryptoKey // 🔐 Chiave privata dell'ente per crittografare
      // 🔐 Chiave privata dell'ente per crittografare
);
    
    const encryptedResponse = {
      nonce: naclUtil.encodeBase64(nonce),
      ciphertext: naclUtil.encodeBase64(encryptedMessageBytes),
      issuerPublicCryptoKey: issuerPublicCryptoKey, // chiave pubblica issuer
      clientPublicCryptoKey: naclUtil.encodeBase64(clientPublicCryptoKeyBytes), // chiave pubblica client
    };

    console.log("✅ VC criptata pronta per l'invio:", JSON.stringify(encryptedResponse, null, 2));

    // 🔹 Ritorniamo la VC criptata come risposta
    return encryptedResponse;

  } catch (error) {
    console.error("❌ Errore nella creazione e crittografia della VC:", error.message);
    throw error;
  }
}
import net from "net";

export async function findAvailablePort(startPort = 3000) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(startPort, () => {
      server.close(() => resolve(startPort)); // 🔹 La porta è libera
    });
    server.on("error", () => resolve(findAvailablePort(startPort + 1))); // 🔹 Porta occupata, cerca successiva
  });
}


