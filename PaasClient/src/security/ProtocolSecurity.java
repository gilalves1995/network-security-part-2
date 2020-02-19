package security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public abstract class ProtocolSecurity {
	
	// Keystore Settings 
    protected static final String KMF_TYPE = "SunX509";
    
    // TLS Settings
    protected static final String TLS_VERSION = "TLSv1.2";
	
	// Algorithms Settings
	protected static final String SIGNATURE_ALGORITHM = "SHA512withRSA";
	protected static final String CIPHERSUITE = "AES/ECB/PKCS5Padding";
	private static final String ENCRYPTION_ALG = "AES";
	private static final int KEY_BYTES = 24;
	protected static final String DEFAULT_PROVIDER = "BC";
	private static final String DIFFIE_HELLMAN_ALG = "DH";
	
	
	// Other
	public static final int NONCE_SIZE = 4;
	private static BigInteger g512 = new BigInteger(
            "153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7"
          + "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b"
          + "410b7a0f12ca1cb9a428cc", 16);
    private static BigInteger p512 = new BigInteger(
            "9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387"
          + "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b"
          + "f0573bf047a3aca98cdf3b", 16);
    
    
    // Security Settings
 	DHParameterSpec dhParams; 
 	KeyPairGenerator keyGenerator;
 	KeyAgreement keyAgreement;
 	KeyPair pair;
 	
 	protected Cipher cipher;
	protected Signature signature;
	protected Keystore keystore;
 	
 	final SecureRandom random;
 	
 	// Communication variables 
 	BufferedReader inputStream;
 	PrintWriter outputStream;
 	
 	protected String keystoreFile;
 	protected String keystoreType;
 	protected String keystorePass;
 	
    
	
	public ProtocolSecurity(String keystoreFile, String keystoreType, String keystorePass) {
		dhParams = new DHParameterSpec(g512, p512);
		try {
			keyGenerator = KeyPairGenerator.getInstance(DIFFIE_HELLMAN_ALG, DEFAULT_PROVIDER);
			keyAgreement = KeyAgreement.getInstance(DIFFIE_HELLMAN_ALG, DEFAULT_PROVIDER);

		} catch (Exception e) {
			e.printStackTrace();
		} 
		pair = null;
		cipher = null;
		signature = null;
		keystore = null;
		random = new SecureRandom();
		inputStream = null;
		outputStream = null;
		
		this.keystoreFile = keystoreFile;
		this.keystoreType = keystoreType;
		this.keystorePass = keystorePass;
	}
	
	
	// Generates a key using Diffie-Hellman's scheme (that will be the same in the other party) - keyBytes are the bytes of public number
	public Key generateCommonKey(byte [] keyBytes) {
		PublicKey key;
		try {
			key = KeyFactory.getInstance(DIFFIE_HELLMAN_ALG).generatePublic(new X509EncodedKeySpec(keyBytes));

			keyAgreement.doPhase(key, true);
			return new SecretKeySpec(keyAgreement.generateSecret(), 0, KEY_BYTES, ENCRYPTION_ALG);
		} catch (Exception e) {
			e.printStackTrace();
		} 
		return null;
	}
	
	
	// Generates a Diffie-Hellman public number 
	public byte [] generatePublicNumber() {
		try {
			keyGenerator.initialize(dhParams);
			pair = keyGenerator.generateKeyPair();
			keyAgreement.init(pair.getPrivate());
			
			Key publicKey = pair.getPublic();
			
			return publicKey.getEncoded();
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public byte [] generateNonce() {
		byte [] nonce = new byte[NONCE_SIZE];
		random.nextBytes(nonce);
		
		return nonce;
	}
	

	// Increments a given nonce
	public static byte [] incrementNonce(byte [] nonce) {
		ByteBuffer fromBytes, fromInt;
		fromBytes = ByteBuffer.wrap(nonce);
		fromInt = ByteBuffer.allocate(Integer.BYTES);
		
		int toInt = fromBytes.getInt();
		toInt ++;
		fromInt.putInt(toInt);
		
		return fromInt.array();
	}
	
	// Writes a string to the communication socket
	public void writeToSocket(String output) {
		outputStream.println(output);
	}
	
	// Reads a string from the communication socket
	public String readFromSocket() throws IOException {
		return inputStream.readLine();
	}
		
	// Handles the TLS connection 
	public abstract void handleTLSConnection(String address, int port)
		throws Exception;
	
	
	
	public void printBytes(byte [] bytes) {
		for(int i = 0; i < bytes.length; i++) {
			System.out.print(bytes[i] + " ");
		
		}
	}

}
