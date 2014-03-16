package com.azhar.security.protector.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import com.azhar.security.protector.IEncrypterDecryptor;


/**
 * Class that implements the encryption logic for TripleDES
 *
 * @author azhar
 */
public class TripleDESEncrypter implements IEncrypterDecryptor {
    // Default key specification to be used for encryption

    private Cipher cipher;
  //default key if not set with setEncryption key
    private  String encryptKey = "KsayToDymoTPs085$312rdse";

    public TripleDESEncrypter() throws NoSuchAlgorithmException, NoSuchPaddingException {
        cipher = Cipher.getInstance("DESede");
    }

    /* (non-Javadoc)
     * @see com.bondrewards.security.Encrypter#encrypt(java.lang.String, java.lang.String)
     */
    public void encryptFile(File read, File write) {
        {
            InputStream in = null;
            OutputStream out = null;
            OutputStream fileOut = null;
            try {
                cipher.init(Cipher.ENCRYPT_MODE, getSecretKeySpec(encryptKey));
                in = new FileInputStream(read);
                fileOut = new FileOutputStream(write);
                out = new CipherOutputStream(fileOut, cipher);
                int redbytes = 0;
                byte[] buffer = new byte[1024];
                while ((redbytes = in.read(buffer)) >= 0) {
                    out.write(buffer, 0, redbytes);
                }
                // read.delete();
                write.renameTo(read);
            } catch (FileNotFoundException ex) {
                ex.printStackTrace();
            } catch (IOException ex) {
                ex.printStackTrace();
            } catch (InvalidKeyException ik) {
                ik.printStackTrace();
            } finally {
                try {
                    out.close();
                    in.close();
                    fileOut.close();

                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        }
    }
    /* (non-Javadoc)
     * @see com.bondrewards.security.Encrypter#decrypt(java.lang.String)
     */

    public void decryptFile(File read, File write) {
        InputStream filein = null;
        InputStream in = null;
        OutputStream fileOut = null;
        try {
            cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(encryptKey));
            filein = new FileInputStream(read);
            fileOut = new FileOutputStream(write);
            in = new CipherInputStream(filein, cipher);
            int redbytes = 0;
            byte[] buffer = new byte[1024];
            while ((redbytes = in.read(buffer)) != -1) {
               // System.out.println("bytes read after decryption :" + redbytes);
                fileOut.write(buffer, 0, redbytes);
            }
            fileOut.flush();
            // read.delete();
            write.renameTo(read);
        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        } catch (InvalidKeyException ik) {
            ik.printStackTrace();
        } finally {
            try {
                in.close();
                filein.close();
                fileOut.close();
               
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }


        /*try{
        cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(encryptKey));
        byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer("");
        byte[] utf8 = cipher.doFinal(dec);
        new String(utf8, "UTF8");
        }catch(InvalidKeyException ik){
        ik.printStackTrace();
        }catch(IllegalBlockSizeException ib){
        ib.printStackTrace();
        }catch(BadPaddingException bp){
        bp.printStackTrace();
        }catch(IOException io){
        io.printStackTrace();
        }*/
    }

    /**
     * @param encryptKey
     * @return
     */
    private SecretKeySpec getSecretKeySpec(String encryptKey) {
        return new SecretKeySpec(encryptKey.getBytes(), "DESede");
    }

	@Override
   public String encryptData(String plainText) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,UnsupportedEncodingException{
		cipher.init(Cipher.ENCRYPT_MODE, getSecretKeySpec(encryptKey));
		byte[] utf8 = plainText.getBytes("UTF8");
		byte[] enc = cipher.doFinal(utf8);
		return new sun.misc.BASE64Encoder().encode(enc);
	}
    
	@Override
    public String decryptData(String encryptedText)throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException{
		cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(encryptKey));
		byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer(encryptedText);
		byte[] utf8 = cipher.doFinal(dec);
		return new String(utf8, "UTF8");
    }

	@Override
     public void setEncryptionKey(String key) {
	     this.encryptKey = key;
	     
     }
    
}