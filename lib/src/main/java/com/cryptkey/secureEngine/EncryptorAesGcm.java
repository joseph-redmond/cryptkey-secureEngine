package com.cryptkey.secureEngine;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptorAesGcm {
    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int KEY_ITERATION_COUNT = 1000000;
    private static final int KEY_LENGTH_BIT = 256;
    private char[] password;
    
    public EncryptorAesGcm(char[] password) {
    	this.password = password;
    }
    
    
    public void setPassword(char[] password) {
    	this.password = password;
    }
    
    protected static byte[] getRandomNonce(int numBytes){
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static SecretKey getAESKey(int keySize) throws NoSuchAlgorithmException{
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(keySize, SecureRandom.getInstanceStrong());
        return keyGen.generateKey();
    }
    
    private void zeroOutPassword() {
    	for(int i = 0; i < this.password.length; i++) {
    		this.password[i] = '0';
    	}
    }
    private void zeroOutByteArray(byte[] array) {
    	for(int i = 0; i < array.length; i++) {
    		array[i] = 0;
    	}
    }

    private SecretKey getAESKeyFromPassword(byte[] initVector) throws NoSuchAlgorithmException, InvalidKeySpecException{
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(this.password, initVector, KEY_ITERATION_COUNT, KEY_LENGTH_BIT);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM);
        zeroOutPassword();
        return secret;
    }

    public byte[] encryptData(byte[] dataToEncrypt) {
        try{
        	byte[] initVector = EncryptorAesGcm.getRandomNonce(IV_LENGTH_BYTE);
            SecretKey key = this.getAESKeyFromPassword(initVector);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BIT, initVector));
            byte[] encryptedData = cipher.doFinal(dataToEncrypt);
            return prefixEmbedIV(initVector, encryptedData);
        }
        catch(Exception e){
            return null;
        } finally {
        	zeroOutByteArray(dataToEncrypt);
        }
    }
    
    public byte[] prefixEmbedIV(byte[] initVector, byte[] encryptedData) {
    	byte[] encryptedDataWithIv = ByteBuffer.allocate(initVector.length + encryptedData.length)
                .put(initVector)
                .put(encryptedData)
                .array();
        return encryptedDataWithIv;
    }
    
    public static byte[] getIV(byte[] encryptedData) {
    	ByteBuffer bb = ByteBuffer.wrap(encryptedData.clone());
        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);
        return iv;
    }
    
    public static byte[] getDataWithoutIV(byte[] encryptedData) {
    	ByteBuffer bb = ByteBuffer.wrap(encryptedData.clone());
        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);
        byte[] encrypted = new byte[bb.remaining()];
        bb.get(encrypted);
        return encrypted;
    }
    
    private static Cipher setupCipher(SecretKey key, byte[] initVector, int cryptMode) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    	Cipher cipher = Cipher.getInstance(CIPHER);
    	cipher.init(cryptMode, key, new GCMParameterSpec(TAG_LENGTH_BIT, initVector));
    	return cipher;
    }


    public byte[] decryptData(byte[] encryptedData){
        try{
        	byte[] data = getDataWithoutIV(encryptedData);
        	byte[] initVector = getIV(encryptedData);
        	SecretKey key = this.getAESKeyFromPassword(initVector);
        	Cipher cipher = setupCipher(key, initVector, Cipher.DECRYPT_MODE);
            return cipher.doFinal(data);
        }
        catch(Exception e){
            return null;
        } finally {
        	zeroOutByteArray(encryptedData);
        }
    }
}