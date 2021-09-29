package com.cryptkey.secureEngine;

import org.junit.Test;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;

public class EncryptorAesGcmTest {
	private static final String ENCODING = "UTF-8";
    
    @Test public void encryptStringReturnsEncryptedString() throws UnsupportedEncodingException {
    	EncryptorAesGcm crypt = new EncryptorAesGcm("password".toCharArray());
    	String stringToEncrypt = "This is the string i am going to encrypt";
    	byte[] encryptedData = crypt.encryptData(stringToEncrypt.getBytes(ENCODING));
    	
    	assertNotEquals(new String(encryptedData, ENCODING), stringToEncrypt);
    	assertNotNull(encryptedData);
    	assertTrue(encryptedData.length > 0);
    }
    
    @Test public void decryptStringReturnsDecryptedString() throws UnsupportedEncodingException {
    	EncryptorAesGcm crypt = new EncryptorAesGcm("password".toCharArray());
    	String stringToEncrypt = "This is the string i am going to encrypt";
    	byte[] encryptedData = crypt.encryptData(stringToEncrypt.getBytes(ENCODING));
    	crypt.setPassword("password".toCharArray());
    	byte[] decryptedData = crypt.decryptData(encryptedData);
    	
    	assertNotEquals(encryptedData, decryptedData);
    	assertNotNull(decryptedData);
    	assertEquals(new String(decryptedData, ENCODING), stringToEncrypt);
    }
    
    @Test public void getIVReturnsCorrentIV() throws UnsupportedEncodingException {
    	EncryptorAesGcm crypt = new EncryptorAesGcm("password".toCharArray());
    	String stringToEncrypt = "This is the string i am going to encrypt";
    	byte[] encryptedData = crypt.encryptData(stringToEncrypt.getBytes(ENCODING));
    	byte[] iv = EncryptorAesGcm.getIV(encryptedData);
    	byte[] randomNonce = EncryptorAesGcm.getRandomNonce(12);
    	
    	assertNotNull(iv);
    	assertTrue(iv.length > 0);
    	assertEquals(iv.length, randomNonce.length);
    }
}
