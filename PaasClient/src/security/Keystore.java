package security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.crypto.SecretKey;


public class Keystore {
	
	// Exceptions 
	private static final String KEYSTORE_EXCEPTION = "Keystore exception was thrown.";

	KeyStore keystore;
	
	private final String keystoreFile;
	private final String keystoreType;
	private final String keystorePass;
	
	public Keystore(String file, String type, String pass) {
		keystoreFile = file;
		keystoreType = type;
		keystorePass = pass;
		
		try {
			keystore = KeyStore.getInstance(keystoreType);
		} catch (KeyStoreException e) {
			System.out.println(KEYSTORE_EXCEPTION);
		}
	}
	
	// Initializes keystore 
	public void initialize() throws Exception {
		File file = new File(keystoreFile);
		if(file.exists()) {
			keystore.load(new FileInputStream(file), keystorePass.toCharArray());
		} else {
			keystore.load(null, null);
			keystore.store(new FileOutputStream(file), keystorePass.toCharArray());
		}
	}
	
	// Returns an entry based on the name of that entry
	public Key getEntry(String keyName) throws Exception {
		PasswordProtection keyPassword = new PasswordProtection(keystorePass.toCharArray());
		Entry entry = keystore.getEntry(keyName, keyPassword); 
		return ((SecretKeyEntry) entry).getSecretKey();
	}
	
	
	// Stores a new key in keystore
	public void store(String entryName, Key key) throws Exception {
		PasswordProtection entryPassword = new PasswordProtection(keystorePass.toCharArray());
		SecretKeyEntry entry = new SecretKeyEntry((SecretKey)key);
		keystore.setEntry(entryName, entry, entryPassword);	
		keystore.store(new FileOutputStream(keystoreFile), keystorePass.toCharArray());
	}
	
	// Returns a private key
	public PrivateKey getPrivateKey(String alias) {
		Key key;
		try {
			key = keystore.getKey(alias, keystorePass.toCharArray());
			return (PrivateKey) key;
		} catch (Exception e) {
			e.printStackTrace();
		} 
		return null;
	}
	
	// Returns a public certificate key
	public PublicKey getPublicKey(String alias) {
		Certificate cert;
		try {
			cert = keystore.getCertificate(alias);
			PublicKey publicKey = cert.getPublicKey();
			return publicKey;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return null;
	}
	

}
