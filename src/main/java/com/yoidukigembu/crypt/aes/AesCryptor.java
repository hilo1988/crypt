package com.yoidukigembu.crypt.aes;

import com.yoidukigembu.crypt.constants.CryptConstants;
import com.yoidukigembu.crypt.exception.CryptException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.SecureRandom;

/**
 * AES暗号化を行うクラス
 *
 * @author hilo
 */
public class AesCryptor extends BaseAes {

    /**
     * AES
     */
    private static final String AES = "AES";


    /**
     * 暗号化するAESのbitの長さを指定してインスタンスを生成<br>
     * 生成されるキーはランダム
     */
    public AesCryptor(int bitLength) {
        super(generateRandomKey(bitLength));
    }

    /**
     * キーを指定してインスタンスを生成
     */
    public AesCryptor(Key key) {
        super(key);
    }

    /**
     * キーを指定してインスタンスを生成
     */
    public AesCryptor(byte[] key) {
        super(key);
    }

    /**
     * @deprecated this class does not use IV.
     */
    @Deprecated
    @Override
    public void setIv(byte[] iv) {
        throw new UnsupportedOperationException("this class does not use IV.");
    }


    /**
     * @deprecated this class does not use IV.
     */
    @Deprecated
    @Override
    public byte[] getIv() {
        throw new UnsupportedOperationException("this class does not use IV.");
    }

    /**
     * @deprecated this class does not use IV.
     */
    @Deprecated
    @Override
    public boolean existsIv() {
        return false;
    }

    @Override
    String getTransformation() {
        return AES;
    }

    /**
     * AESで暗号化
     *
     * @param data 暗号化する文字
     * @return 暗号化されたデータ
     */
    public byte[] encryptCbc(String data) {
        return encrypt(data, CryptConstants.UTF8);
    }



    /**
     * AESで復元
     *
     * @param data 復元するデータ
     * @return 復元されたデータ
     */
    public byte[] decrypt(byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance(AES);
            cipher.init(Cipher.DECRYPT_MODE, getKey());
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CryptException("data could not be decrypted CBC", e);
        }
    }


    /**
     * AESで復元して文字列で返す
     *
     * @param data 復元するデータ
     * @return 復元されたデータの文字列
     */
    public String decryptString(byte[] data) {
        return decryptString(data, CryptConstants.UTF8);
    }

    /**
     * AESで復元して文字列で返す
     *
     * @param data   復元するデータ
     * @param encode エンコード文字
     * @return 復元されたデータの文字列
     */
    public String decryptString(byte[] data, String encode) {
        byte[] desc = decrypt(data);
        try {
            return new String(desc, encode);
        } catch (UnsupportedEncodingException e) {
            throw new CryptException(String.format("encode[%s] is not supported.", encode), e);
        }
    }


    /**
     * ランダムキーの作成
     *
     * @param bitLength bitの長さ
     * @return ランダムキー
     */
    private static Key generateRandomKey(int bitLength) {
        try {
            KeyGenerator generator = KeyGenerator.getInstance(AES);
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            generator.init(bitLength, random);
            return generator.generateKey();
        } catch (Exception e) {
            throw new CryptException("randomKey could not be generated", e);
        }
    }

}
