package com.cryptkey.secureEngine;

public class ArrayWipeUtility {

	protected static void zeroOutCharArray(char[] array) {
		for(int i = 0; i < array.length; i++) {
			array[i] = '0';
		}
	}

	protected static void zeroOutByteArray(byte[] array) {
		for(int i = 0; i < array.length; i++) {
			array[i] = 0;
		}
	}
}