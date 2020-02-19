package security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;

import exceptions.AuthenticityVerificationException;
import exceptions.IntegrityVerificationException;
import utils.Utils;

public class RedisSecurity {
	
	private String ciphersuite, hashAlgorithm, macAlgorithm, signatureAlgorithm;
	
	Signature signature;
	KeyPairGenerator keyPairGenerator;
	KeyGenerator generator;
	Keystore jceksKeystore, jksKeystore;
	MessageDigest hash;
	Cipher cipher;
	Mac mac;
	
	// Keys 
	Key macKey, cipherKey;
	PublicKey publicKey;
	PrivateKey privateKey;
	
	IvParameterSpec iv;
	
	
	// Configuration of 
	private String redisKeystoreFile;
	private String redisKeystoreType;
	private String redisKeystorePass;
	
	private String clientKeystoreFile;
	private String clientKeystoreType;
	private String clientKeystorePass;
	
	private String clientAlias;
	
	private String macKeyAlias;
	private String encryptionKeyAlias;
	
	public RedisSecurity(String redisKeystoreFile, String redisKeystoreType, String redisKeystorePass, 
			String clientKeystoreFile, String clientKeystoreType, String clientKeystorePass, String clientAlias, String macKeyAlias,
				String encryptionKeyAlias) {
		
		this.redisKeystoreFile = redisKeystoreFile;
		this.redisKeystoreType = redisKeystoreType;
		this.redisKeystorePass = redisKeystorePass;
		this.clientKeystoreFile = clientKeystoreFile;
		this.clientKeystoreType = clientKeystoreType;
		this.clientKeystorePass = clientKeystorePass;
		
		this.clientAlias = clientAlias;
		
		this.macKeyAlias = macKeyAlias;
		this.encryptionKeyAlias = encryptionKeyAlias;
		
		config();
	}

	// Digests field 
	public byte [] digest(String field) {
		byte [] bytes = field.getBytes();
		return hash.digest(bytes);
	}
	
	// Returns the length of the digest 
	public int getDigestLength() {
		return hash.getDigestLength();
	}
	
	// Starts encryption process 
	public byte [] startEncryption(byte [] plaintext)  {
		try {
			Key key = jceksKeystore.getEntry(macKeyAlias);
			mac.init(key);
			byte [] ciphertext = doSignature(plaintext);
			byte [] macBytes = mac.doFinal(ciphertext);
			
			byte [] payload = new byte[ciphertext.length + macBytes.length];
			System.arraycopy(ciphertext, 0, payload, 0, ciphertext.length);
			System.arraycopy(macBytes, 0, payload, ciphertext.length, macBytes.length);
			
			return payload;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// Encrypts plaintext
	public byte [] encrypt(byte [] plaintext) {
		byte [] ciphertext;
		try {
			Key key = jceksKeystore.getEntry(encryptionKeyAlias);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			ciphertext = cipher.doFinal(plaintext);

			return ciphertext;
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// Starts decryption process
	public byte [] startDecryption(byte [] ciphertext) {
		try {
			byte [] signedItems = new byte[ciphertext.length - mac.getMacLength()];
			System.arraycopy(ciphertext, 0, signedItems, 0, signedItems.length);
			
			byte [] macBytes = new byte[mac.getMacLength()];
			System.arraycopy(ciphertext, signedItems.length, macBytes, 0, macBytes.length);
			
			if(!MessageDigest.isEqual(mac.doFinal(signedItems), macBytes))
				throw new IntegrityVerificationException();
			
			byte [] plaintext = verifySignature(signedItems);
			return plaintext;
		
		} catch(Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// Verifies signature
	public byte [] verifySignature(byte [] payload) throws AuthenticityVerificationException {
		byte [] ciphertext, signatureBytes;
		try {
			
			byte [] signatureSize = new byte[Integer.BYTES];
			System.arraycopy(payload, 0, signatureSize, 0, Integer.BYTES);
			ByteBuffer byteBuffer = ByteBuffer.wrap(signatureSize);
			
			signatureBytes = new byte[byteBuffer.getInt()];
			System.arraycopy(payload, Integer.BYTES, signatureBytes, 0, signatureBytes.length);
			
			ciphertext = new byte[payload.length - signatureBytes.length - Integer.BYTES];
			System.arraycopy(payload, Integer.BYTES + signatureBytes.length, ciphertext, 0, ciphertext.length);
				
			PublicKey publicKey = jksKeystore.getPublicKey(clientAlias);
			
			signature.initVerify(publicKey);
			signature.update(ciphertext);
			
			if(!signature.verify(signatureBytes)) 
				throw new AuthenticityVerificationException();
			
			byte [] plaintext = decrypt(ciphertext);
			return plaintext;
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// Descrypts ciphertext
	public byte [] decrypt(byte [] ciphertext) {
			
		byte [] plaintext;
		try {
			Key key = jceksKeystore.getEntry(encryptionKeyAlias);
			cipher.init(Cipher.DECRYPT_MODE, key);
			plaintext = cipher.doFinal(ciphertext);
				
			return plaintext;		
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	
	// Does a signature
	public byte [] doSignature(byte [] plaintext) {
		byte [] payload;
		byte [] ciphertext = encrypt(plaintext);
		try {
			
			PrivateKey privateKey = jksKeystore.getPrivateKey(clientAlias);
			signature.initSign(privateKey);
			signature.update(ciphertext);
			
		    byte [] signatureBytes = signature.sign();
		    byte [] signatureSize = ByteBuffer.allocate(Integer.BYTES).putInt(signatureBytes.length).array();
		    
		    payload = new byte [Integer.BYTES + signatureBytes.length + ciphertext.length]; 
		    System.arraycopy(signatureSize, 0, payload, 0, Integer.BYTES);
		    System.arraycopy(signatureBytes, 0, payload, Integer.BYTES, signatureBytes.length);
		    System.arraycopy(ciphertext, 0, payload, Integer.BYTES + signatureBytes.length, ciphertext.length);
		    
		    
			return payload;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	
	public String buildKey(String key) {
        byte[] digest = hash.digest(key.getBytes());
        byte[] hashedKey = Arrays.copyOfRange(digest, 0, 4);

        return Utils.toHexa(hashedKey);
    }
	
	
	public String encryptValue(String value) throws SignatureException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
		try (ByteArrayOutputStream bStream = new ByteArrayOutputStream()) {
			mac.init(macKey);
			cipherInit(Cipher.ENCRYPT_MODE);
			signature.initSign(privateKey);

			byte[] cipherBytes = cipher.doFinal(value.getBytes());
			bStream.write(cipherBytes);

			signature.update(cipherBytes);
			byte[] signBytes = signature.sign();
			bStream.write(signBytes);

			byte[] macBytes = mac.doFinal(bStream.toByteArray());

			return (Base64.getEncoder().encodeToString(cipherBytes) + ':'
					+ Base64.getEncoder().encodeToString(signBytes) + ':'
					+ Base64.getEncoder().encodeToString(macBytes));

		}
	}

	public String decryptValue(String encryptedValue) throws Exception {
		String[] components = encryptedValue.split(":");
		byte[] cipherBytes = Base64.getDecoder().decode(components[0]);
		byte[] signatureBytes = Base64.getDecoder().decode(components[1]);
		byte[] macBytes = Base64.getDecoder().decode(components[2]);

		// Check consistency
		mac.init(macKey);
		byte[] authenticatedBytes = Utils.concat(cipherBytes, signatureBytes);
		byte[] expectedMacBytes = mac.doFinal(authenticatedBytes);
		if (!Arrays.equals(macBytes, expectedMacBytes))
			throw new Exception();

		// Check authenticity
		signature.initVerify(publicKey);
		signature.update(cipherBytes);
		if (!signature.verify(signatureBytes))
			throw new Exception();

		// Decipher to get plaintext bytes
		cipherInit(Cipher.DECRYPT_MODE);
		byte[] value = cipher.doFinal(cipherBytes);

		return new String(value);
	}
	
	
	private void cipherInit(int mode) throws InvalidAlgorithmParameterException, InvalidKeyException {
        final String CIPHER_ALGORITHM = cipher.getAlgorithm().split("/")[1];

        switch (CIPHER_ALGORITHM) {
            case "CBC":
                cipher.init(mode, cipherKey, iv);
                break;
            case "ECB":
            default:
                cipher.init(mode, cipherKey);
        }
    }
	

	private void config() {
		String [] settings = Utils.readCiphersuiteFile();
		hashAlgorithm = settings[0];
		ciphersuite = settings[1];
		macAlgorithm = settings[2];
		signatureAlgorithm = settings[3];
		iv = new IvParameterSpec(settings[4].getBytes());

		try {
			jceksKeystore = new Keystore(redisKeystoreFile, redisKeystoreType, redisKeystorePass);
			jceksKeystore.initialize();
			jksKeystore = new Keystore(clientKeystoreFile, clientKeystoreType, clientKeystorePass);
			jksKeystore.initialize();
			
			macKey = jceksKeystore.getEntry(macKeyAlias);
			cipherKey = jceksKeystore.getEntry(encryptionKeyAlias);
			
			publicKey = jksKeystore.getPublicKey(clientAlias);
			privateKey = jksKeystore.getPrivateKey(clientAlias);
			
			hash = MessageDigest.getInstance(hashAlgorithm);
			cipher = Cipher.getInstance(ciphersuite);
			mac = Mac.getInstance(macAlgorithm);
			signature = Signature.getInstance(signatureAlgorithm, "BC");
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
}
