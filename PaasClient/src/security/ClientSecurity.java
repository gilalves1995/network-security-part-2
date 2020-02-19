package security;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import exceptions.AuthenticityVerificationException;

public class ClientSecurity extends ProtocolSecurity {
	
    private SSLSocket socket;
    
	public ClientSecurity(String keystoreFile, String keystoreType, String keystorePass) {
		super(keystoreFile, keystoreType, keystorePass);

		try {
			keystore = new Keystore(keystoreFile, keystoreType, keystorePass);
			keystore.initialize();
			
			signature = Signature.getInstance(SIGNATURE_ALGORITHM, DEFAULT_PROVIDER);
			cipher = Cipher.getInstance(CIPHERSUITE);
			
			socket = null;
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	// Retrieves the public key from the certificate of the server
	public PublicKey getPublicKey(String alias) {
		PublicKey key = keystore.getPublicKey(alias);
		return key;
	}
	
	// Verifies the digital signature
	public void verifySignature(byte [] signatureBytes, byte [] toVerify, PublicKey key) {
		try {
			signature.initVerify(key);
			signature.update(toVerify);
			
			if(!signature.verify(signatureBytes)) 
				throw new AuthenticityVerificationException();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	// Performs decryption 
	public byte [] decrypt(Key key, byte [] ciphertext) {
		try {
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte [] plaintext = cipher.doFinal(ciphertext);
			return plaintext;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// Compares the received nonce to the nonce previously generated
	public boolean isReceivedNonceValid(byte [] lastGenerated, byte [] received) {
		byte [] incrementedNonce = incrementNonce(lastGenerated);
		return MessageDigest.isEqual(incrementedNonce, received);
	}

	
	public void handleTLSConnection(String address, int port) throws Exception {
		System.setProperty("javax.net.ssl.keyStore", keystoreFile);
		System.setProperty("javax.net.ssl.keyStorePassword", keystorePass);
		System.setProperty("javax.net.ssl.trustStore", keystoreFile);
		System.setProperty("javax.net.ssl.trustStorePassword", keystorePass);
		System.setProperty("https.protocols", "TLSv1,TLSv1.1,TLSv1.2");
		
		// Initialize keystore 
		FileInputStream fileStream = new FileInputStream(keystoreFile);
		KeyStore keystore = KeyStore.getInstance(keystoreType);
		keystore.load(fileStream, keystorePass.toCharArray());
		
		// Initialize Key manager factory 
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KMF_TYPE);
		kmf.init(keystore, keystorePass.toCharArray());
		
		
		// Initialize server
		SSLContext context = SSLContext.getInstance(TLS_VERSION);
		context.init(kmf.getKeyManagers(), null, new SecureRandom());

		// Server socket creation
		socket = (SSLSocket) context.getSocketFactory().createSocket(address, port);
			
		socket.startHandshake();
		
		
		outputStream = new PrintWriter(socket.getOutputStream(), true);
		inputStream = new BufferedReader(new InputStreamReader(socket.getInputStream()));
	}
	
}
