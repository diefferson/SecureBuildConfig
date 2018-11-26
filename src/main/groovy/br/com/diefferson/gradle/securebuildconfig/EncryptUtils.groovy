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

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

/**
 * @author Santos Diefferson
 */
final class EncryptUtils{

    private static SecretKeySpec secretKey
    private static byte[] key

    static void setKey(String myKey)
    {
        MessageDigest sha = null
        try {
            key = myKey.getBytes("UTF-8")
            sha = MessageDigest.getInstance("SHA-1")
            key = sha.digest(key)
            key = Arrays.copyOf(key, 16)
            secretKey = new SecretKeySpec(key, "AES")
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace()
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace()
        }
    }

    static String encrypt(String strToEncrypt, String secret)
    {
        try
        {
            setKey(secret)
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")))
        }
        catch (Exception e)
        {
            System.out.println("Error while encrypting: " + e.toString())
        }
        return null
    }

    static String decrypt(String strToDecrypt, String secret)
    {
        try
        {
            setKey(secret)
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING")
            cipher.init(Cipher.DECRYPT_MODE, secretKey)
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)))
        }
        catch (Exception e)
        {
            System.out.println("Error while decrypting: " + e.toString())
        }
        return null
    }
}