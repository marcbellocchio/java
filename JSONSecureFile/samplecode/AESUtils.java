package com.trulytech.mantis.util;
 
import gnu.crypto.mode.IMode;
import gnu.crypto.mode.ModeFactory;
import gnu.crypto.pad.IPad;
import gnu.crypto.pad.PadFactory;
import java.util.HashMap;
import java.util.Map;
 
/**
 *
 * <p>
 * Title: Mantis
 * </p>
 *
 * <p>
 * Description: AES CBC16 ??????? ????????????16Byte,??????IV=0
 * </p>
 *
 * <p>
 * Copyright: Copyright (c) 2002
 * </p>
 *
 * <p>
 * Company:
 * </p>
 *
 * @author Wang Xian
 * @version 1.0
 */
public class AESUtil {
 
    /**
     * ???? Block=128
     *
     * @param source
     *            String ????
     * @param mykey
     *            byte[] Key
     * @param i_iv
     *            byte[] ????
     * @return byte[] ??????byte
     */
    public static byte[] encryptString(byte[] source, byte[] mykey, byte[] i_iv) {
        byte[] ct = null;
 
        try {
            IPad padding = PadFactory.getInstance("PKCS7");
            padding.init(16);
            IMode mode = ModeFactory.getInstance("CBC", "AES", 16);
            Map attributes = new HashMap();
            byte[] pt1 = source;
            byte[] pad = padding.pad(pt1, 0, pt1.length);
            byte[] pt = null;
            // ???????????
            if (pad.length == 16) {
                pt = new byte[pt1.length];
                System.arraycopy(pt1, 0, pt, 0, pt1.length);
            } else {
                pt = new byte[pt1.length + pad.length];
                System.arraycopy(pt1, 0, pt, 0, pt1.length);
                System.arraycopy(pad, 0, pt, pt1.length, pad.length);
            }
 
            ct = new byte[pt.length];
 
            byte[] iv = i_iv;
            byte[] key = mykey;
            attributes.put(IMode.KEY_MATERIAL, key);
            attributes.put(IMode.CIPHER_BLOCK_SIZE, new Integer(16));
            attributes.put(IMode.IV, iv);
            attributes.put(IMode.STATE, new Integer(IMode.ENCRYPTION));
            mode.init(attributes);
 
            for (int i = 0; i + 16 <= pt.length; i += 16) {
                mode.update(pt, i, ct, i);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
 
        return ct;
    }
 
    /**
     * ????
     *
     * @param source
     *            byte[] ??????byte[]
     * @param mykey
     *            byte[] Key
     * @param i_iv
     *            byte[] ????
     * @return String ???????byte[]
     */
    public static byte[] decryptString(byte[] source, byte[] mykey, byte[] i_iv) {
 
        byte[] out = null;
        try {
            IPad padding = PadFactory.getInstance("PKCS7");
            padding.init(16);
            IMode mode = ModeFactory.getInstance("CBC", "AES", 16);
            Map attributes = new HashMap();
 
            byte[] iv = i_iv;
            byte[] ct = new byte[source.length];
            byte[] key = mykey;
 
            attributes.put(IMode.KEY_MATERIAL, key);
            attributes.put(IMode.CIPHER_BLOCK_SIZE, new Integer(16));
            attributes.put(IMode.IV, iv);
            attributes.put(IMode.STATE, new Integer(IMode.DECRYPTION));
            mode.init(attributes);
 
            for (int i = 0; i + 16 <= source.length; i += 16) {
                mode.update(source, i, ct, i);
            }
 
            try {
                int unpad = padding.unpad(ct, 0, ct.length);
                out = new byte[ct.length - unpad];
                System.arraycopy(ct, 0, out, 0, out.length);
            } catch (Exception e) {
                out = new byte[ct.length];
                System.arraycopy(ct, 0, out, 0, out.length);
            }
 
        } catch (Exception e) {
            e.printStackTrace();
        }
        return out;
    }
 
    /*
     * Case #1: Encrypting 16 bytes (1 block) using AES-CBC with 128-bit key 
     * Key :
     * 0x06a9214036b8a15b512e03d534120006 
     * IV :
     * 0x3dafba429d9eb430b422da802c9fac41 
     * Plaintext : "Single block msg"
     * Ciphertext: 0xe353779c1079aeb82708942dbe77181a
     *
     * Case #2: Encrypting 32 bytes (2 blocks) using AES-CBC with 128-bit key
     * Key : 0xc286696d887c9aa0611bbb3e2025a45a 
     * IV :
     * 0x562e17996d093d28ddb3ba695a2e6f58 
     * Plaintext :
     * 0x000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f
     * Ciphertext: 
     * 0xd296cd94c2cccf8a3a863028b5e1dc0a
     * 7586602d253cfff91b8266bea6d61ab1
     *
     * public static void main(String args[]) { try { 
     * byte[] key =
     * StringUtils.decodeHex("06a9214036b8a15b512e03d534120006"); 
     * byte[] iv =
     * StringUtils.decodeHex("3dafba429d9eb430b422da802c9fac41"); 
     * byte[] src =
     * "Single block ms".getBytes(); 
     * byte[]
     * desc=AESUtil.encryptString(src,key,iv);
     * System.out.println(StringUtils.encodeHex(desc)); System.out.println(new
     * String(AESUtil.decryptString(desc,key,iv))); } catch (Exception e) {
     * e.printStackTrace(); } }
     */
}