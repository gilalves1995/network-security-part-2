package security;
import java.io.BufferedReader;

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

public class ServerSecurity extends ProtocolSecurity {

	private static final String TLS_CIPHERSUITE_FILE = "tls_ciphersuites.txt";
	
	SSLServerSocket socket;
	SSLSocket clientSocket;
	String alias;

	public ServerSecurity(String keystoreFile, String keystoreType, String keystorePass, String alias) {
		super(keystoreFile, keystoreType, keystorePass);
		this.alias = alias;
		
		keystore = new Keystore(keystoreFile, keystoreType, keystorePass);
		
		try {
			keystore.initialize();
			signature = Signature.getInstance(SIGNATURE_ALGORITHM, DEFAULT_PROVIDER);
			cipher = Cipher.getInstance(CIPHERSUITE);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	// Returns a private key from the Keystore needed for signature 
	public PrivateKey getPrivateKey() {
		PrivateKey key = keystore.getPrivateKey(alias);
		return key;
	}
	
	// Performs digital signature 
	public byte [] doSignature(byte [] toSign, PrivateKey privateKey) {
		try {
			signature.initSign(privateKey);
			signature.update(toSign);
			
		    byte [] signatureBytes = signature.sign();
		    byte [] signatureSize = ByteBuffer.allocate(Integer.BYTES).putInt(signatureBytes.length).array();
		    byte [] toSignSize = ByteBuffer.allocate(Integer.BYTES).putInt(toSign.length).array();
		    
		    byte [] payload = new byte [Integer.BYTES*2 + signatureBytes.length + toSign.length];
		    
		    System.arraycopy(signatureSize, 0, payload, 0, Integer.BYTES);
		    System.arraycopy(signatureBytes, 0, payload, Integer.BYTES, signatureBytes.length);
		    System.arraycopy(toSignSize, 0, payload, Integer.BYTES + signatureBytes.length, Integer.BYTES);
		    System.arraycopy(toSign, 0, payload, Integer.BYTES*2 + signatureBytes.length, toSign.length);
		    
		    return payload;
		    
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// Performs encryption 
	public byte [] encrypt(Key key, byte [] attestProofs) {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte [] ciphertext = cipher.doFinal(attestProofs);
			return ciphertext;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	// Handles TLS connection 
	public void handleTLSConnection(String address, int port) throws Exception {

		System.setProperty("javax.net.ssl.keyStore", keystoreFile);
		System.setProperty("javax.net.ssl.keyStorePassword", keystorePass);
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
		socket = (SSLServerSocket) 
			context.getServerSocketFactory().createServerSocket(port);
		
		String [] suites = getCiphersuiteList();
		socket.setEnabledCipherSuites(suites);
	
		clientSocket = (SSLSocket)socket.accept();
		
		
		outputStream = new PrintWriter(clientSocket.getOutputStream(), true);
		inputStream = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
	}
	
	// Auxiliar method to read the tls ciphersuite file
	private String [] getCiphersuiteList() {
		String [] ciphersuites;
		try {
			BufferedReader reader = new BufferedReader(new FileReader(TLS_CIPHERSUITE_FILE));
			int lineNumber = Integer.parseInt(reader.readLine());
			ciphersuites = new String[lineNumber];
			String line;
			int i = 0;
			while((line = reader.readLine()) != null) {
				ciphersuites[i] = line;
				i++;
			}
			reader.close();
			return ciphersuites;
		} catch(Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}
