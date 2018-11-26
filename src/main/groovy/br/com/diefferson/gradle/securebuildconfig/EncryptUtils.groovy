/* The MIT License (MIT)
 *
 * Copyright (c) 2018 Santos Diefferson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package br.com.diefferson.gradle.securebuildconfig

import sun.misc.BASE64Decoder
import sun.misc.BASE64Encoder

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * @author Santos Diefferson
 */
final class EncryptUtils{

    static String encrypt(String key, String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec("RandomInitVector".getBytes("UTF-8"))
            String encryptedKey  = encode(key, "RandomInitVector")
            SecretKeySpec skeySpec = new SecretKeySpec(encryptedKey.getBytes("UTF-8"), "AES")

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv)

            byte[] encrypted = cipher.doFinal(value.getBytes())
            System.out.println("encrypted string: "
                    + Base64.encodeBase64String(encrypted))

            return Base64.encodeBase64String(encrypted)
        } catch (Exception ex) {
            ex.printStackTrace()
        }

        return null
    }

    static String decrypt(String key, String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec("RandomInitVector".getBytes("UTF-8"))
            String decryptedKey  = decode(key, "RandomInitVector")
            SecretKeySpec skeySpec = new SecretKeySpec(decryptedKey.getBytes("UTF-8"), "AES")

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv)

            byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted))

            return new String(original)
        } catch (Exception ex) {
            ex.printStackTrace()
        }

        return null
    }

    private static String encode(String s, String key) {
        return base64Encode(xorWithKey(s.getBytes(), key.getBytes()))
    }

    private static String decode(String s, String key) {
        return new String(xorWithKey(base64Decode(s), key.getBytes()))
    }

    private static byte[] xorWithKey(byte[] a, byte[] key) {
        byte[] out = new byte[a.length]
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ key[i%key.length])
        }
        return out
    }

    private static byte[] base64Decode(String s) {
        try {
            BASE64Decoder d = new BASE64Decoder()
            return d.decodeBuffer(s)
        } catch (IOException e) {
            throw new RuntimeException(e)
        }
    }

    private static String base64Encode(byte[] bytes) {
        BASE64Encoder enc = new BASE64Encoder()
        return enc.encode(bytes).replaceAll("\\s", "")
    }
}