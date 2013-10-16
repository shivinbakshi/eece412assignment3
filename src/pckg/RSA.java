package pckg;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class RSA {
	
	public RSA(){}
	
/*	public static void rsaKeyPair(UserInterface A){
		IKeyPairGenerator kpg = KeyPairGeneratorFactory.getInstance(Registry.RSA_KPG);
		HashMap map = new HashMap();
		map.put(RSAKeyPairGenerator.MODULUS_LENGTH, 1024);
		kpg.setup(map);
		KeyPair kp = kpg.generate();
		A.privateKey = kp.getPrivate();
		A.publicKey = kp.getPublic();
	}*/

	// Encrypt plain text using public key
	public static byte[] rsaEncrypt(byte[] text, PublicKey key){
		byte[] cipherText = null;
		try{
			// get an RSA cipher and print the provider
			final Cipher cipher = Cipher.getInstance("RSA");
			// encrypt the plain text using the public key
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherText = cipher.doFinal(text);
		} catch (Exception e){
			e.printStackTrace();
		}
		return cipherText;
	}
	
	// Decrypt text using private key
	public static String rsaDecrypt(byte[] text, PrivateKey key){
		byte[] plainText = null;
		try{
			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance("RSA");
			// decrypt the text using the private key
			cipher.init(Cipher.DECRYPT_MODE, key);
			plainText = cipher.doFinal(text);
		} catch (Exception e1){
			e1.printStackTrace();
		}
		return new String(plainText);
	}
	
	public static void generateRsaKeyPair(UserInterface A){
		try{
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			final KeyPair keyPair = keyGen.generateKeyPair();
			A.privateKey = keyPair.getPrivate();
			A.publicKey = keyPair.getPublic();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	// Sign using SHA1withRSA
	public static byte[] sign(String data, PrivateKey key){
		Signature sig = null;
		byte[] realSig = null;
		try {
			sig = Signature.getInstance("SHA1withRSA");
			sig.initSign(key);
			sig.update(data.getBytes());
			realSig = sig.sign();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException i) {
			i.printStackTrace();
		} catch (SignatureException s) {
			s.printStackTrace();
		}
		return realSig;
	}
	
	// Verify SHA1withRSA signature
	public static boolean verifySign(PublicKey key, byte[] sigToVerify, byte[] data){
		Signature sig = null;
		boolean result = false;
		try {
			sig = Signature.getInstance("SHA1withRSA");
			sig.initVerify(key);
			sig.update(data);
			result = sig.verify(sigToVerify);
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException i) {
			i.printStackTrace();
		} catch (InvalidKeyException s) {
			s.printStackTrace();
		}
		return result;
	}
	
	public static int genNonce(){
		SecureRandom sr = null;
		try{
			// Create a secure random number generator
			sr = SecureRandom.getInstance("SHA1PRNG");
			
			// Get 1024 random bits
			byte[] bytes = new byte[1024/8];
			sr.nextBytes(bytes);
			
			// Create two secure number generators with the same seed
			int seedByteCount = 10;
			byte[] seed = sr.generateSeed(seedByteCount);
			
			sr = SecureRandom.getInstance("SHA1PRNG");
			sr.setSeed(seed);
		} catch (NoSuchAlgorithmException e) {
			
		}
		return sr.nextInt();
	}
	
	public static PublicKey getPublicKey(UserInterface a){
		return a.publicKey;
	}
	
	public static PublicKey convertEncodedPublicKeyBytes(byte[] encKey){
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
		PublicKey pubKey = null;
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			pubKey = keyFactory.generatePublic(pubKeySpec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		
		return pubKey;
	}
}
