package com.hilo_islay.crypt.aes;

import com.hilo_islay.crypt.constants.CryptConstants;
import com.hilo_islay.crypt.exception.CryptException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.util.Random;

/**
 * keyに関するインフォクラス
 *
 * @author hilo
 */
public abstract class BaseAes {

    /**
     * キー
     */
    private final Key key;

    /**
     * IV
     */
    private byte[] iv;


    /**
     * キーを指定してインスタンスを生成
     */
    public BaseAes(Key key) {
        this.key = key;
    }

    /**
     * キーを指定してインスタンスを生成
     */
    public BaseAes(byte[] key) {
        this.key = new SecretKeySpec(key, "AES");
    }

    /**
     * キーとIVを指定してインスタンスを生成
     */
    public BaseAes(Key key, byte[] iv) {
        this(key);
        this.iv = iv;
    }

    /**
     * キーとIVを指定してインスタンスを生成
     */
    public BaseAes(byte[] key, byte[] iv) {
        this(key);
        this.iv = iv;
    }

    public Key getKey() {
        return key;
    }

    public byte[] getKeyBytes() {
        return key.getEncoded();
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public byte[] getIv() {
        return iv;
    }

    public boolean existsIv() {
        return iv != null
                && iv.length > 0;
    }


    /**
     * 暗号化
     *
     * @param data 暗号化する文字
     * @return 暗号化されたデータ
     */
    public byte[] encrypt(String data) {
        return encrypt(data, CryptConstants.UTF8);
    }


    /**
     * 暗号化
     *
     * @param data   暗号化する文字
     * @param encode エンコード
     * @return 暗号化されたデータ
     */
    public byte[] encrypt(String data, String encode) {
        try {
            byte[] src = data.getBytes(encode);
            return encrypt(src);
        } catch (UnsupportedEncodingException e) {
            throw new CryptException(String.format("encode[%s] is not supported.", encode), e);
        }
    }

    /**
     * CBCで暗号化
     *
     * @param data 暗号化するデータ
     * @return 暗号化されたデータ
     */
    public byte[] encrypt(byte[] data) {

        try {
            Cipher cipher = Cipher.getInstance(getTransformation());
            if (existsIv()) {
                cipher.init(Cipher.ENCRYPT_MODE, getKey(), new IvParameterSpec(getIv()));
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, getKey());
                setIv(cipher.getIV());
            }
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new CryptException("data could not be encrypted CBC", e);
        }
    }

    abstract String getTransformation();

    public static byte[] generateRandomBytes(int bitLength) {
        byte[] key = new byte[bitLength / 8];
        new Random().nextBytes(key);
        return key;
    }

}
