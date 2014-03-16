
package com.azhar.security.protector;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.NoSuchPaddingException;

import com.azhar.security.protector.IEncrypterDecryptor.ALGORITHMS;
import com.azhar.security.protector.impl.MD5ANDDESEncrypter;
import com.azhar.security.protector.impl.TripleDESEncrypter;


/**
 * 
 * @author azhar
 */
public abstract class EncrypDecryptFactory {

	private static TripleDESEncrypter tripleDescDESEncrypter;
	private static MD5ANDDESEncrypter md5DesEncrpter;

	public static IEncrypterDecryptor getInstance(ALGORITHMS algorithm)
			throws NoSuchAlgorithmException, NoSuchPaddingException {
		if (algorithm.equals(ALGORITHMS.TRIPLEDES)) {
			if (tripleDescDESEncrypter == null) {
				tripleDescDESEncrypter = new TripleDESEncrypter();
			}
			return tripleDescDESEncrypter;
		} else if (algorithm.equals(ALGORITHMS.MD5)) {
			if (md5DesEncrpter == null) {
				try {
					md5DesEncrpter = new MD5ANDDESEncrypter();
				} catch (InvalidKeySpecException ex) {
					ex.printStackTrace();
				}
			}
			return md5DesEncrpter;
		}else{
			throw new NoSuchAlgorithmException("Algorithm not found");
		}
	}

}
