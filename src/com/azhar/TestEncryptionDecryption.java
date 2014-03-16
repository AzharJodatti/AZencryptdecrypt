package com.azhar;

import com.azhar.security.protector.EncrypDecryptFactory;
import com.azhar.security.protector.IEncrypterDecryptor;
import com.azhar.security.protector.IEncrypterDecryptor.ALGORITHMS;


public class TestEncryptionDecryption {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		try{
			IEncrypterDecryptor ed = EncrypDecryptFactory.getInstance(ALGORITHMS.TRIPLEDES);
			String plainText = "This is testing ";
			System.out.println("Before encryption : "+ plainText);
			plainText = ed.encryptData(plainText);
			System.out.println("after encryption : "+ plainText);
			plainText = ed.decryptData(plainText);
			System.out.println("after decryption : "+ plainText);
		}catch(Exception e){
			e.printStackTrace();
		}
	}

}
