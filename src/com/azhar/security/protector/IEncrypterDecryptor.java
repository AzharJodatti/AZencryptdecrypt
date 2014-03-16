
package com.azhar.security.protector;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/**
 *
 * @author azhar
 */
public interface IEncrypterDecryptor {
 
    public enum ALGORITHMS{
    	MD5,TRIPLEDES
    }
    
    /**
     * set the key to be used with encryption and decryption
     * @param key
     */
    public void setEncryptionKey(String key);
    
    
    /**
     * This method reads the data from the input file and writes it to output file in encrypted format 
     * @param read
     * @param write
     */
    public void encryptFile(File inputFile,File outputFile);
    
    /**
     * decrypt the data from input file and writes it to output file in plain text 
     * @param inputFile
     * @param outputFile
     */
    public void decryptFile(File inputFile,File outputFile);
    
    
    /**
     * encrypt the given plain text and returns it. 
     * @param plainText
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws UnsupportedEncodingException
     */
    public String encryptData(String plainText) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,UnsupportedEncodingException;
    
    
    /**
     * decryptes the encrypted text
     * @param encryptedText
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IOException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public String decryptData(String encryptedText)throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException;
    
}
