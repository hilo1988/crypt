package com.yoidukigembu.crypt.aes;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.yoidukigembu.crypt.constants.CryptConstants;
import com.yoidukigembu.crypt.exception.CryptException;
import com.yoidukigembu.crypt.valueobject.CryptData;

/**
 * AES/CBC/PKCS5Padding での暗号化クラス<br>
 * IVを扱うAES
 * @author hilo
 *
 */
public class CbcCryptor extends BaseAes {

	private static final String CBC = "AES/CBC/PKCS5Padding";
	
	/**
	 * 暗号化するAESのbitの長さを指定してインスタンスを生成<br>
	 * 生成されるキーはランダム
	 */
	public CbcCryptor(int bitLength) {
		super(generateRandomKey(bitLength));
	}
	
	/**
	 * キーを指定してインスタンスを生成
	 */
	public CbcCryptor(Key key) {
		super(key);
	}
	
	/**
	 * キーを指定してインスタンスを生成
	 */
	public CbcCryptor(byte[] key) {
		super(key);
	}
	
	/**
	 * キーとIVを指定してインスタンスを生成
	 */
	public CbcCryptor(Key key, byte[] iv) {
		super(key, iv);
	}
	
	/**
	 * キーとIVを指定してインスタンスを生成
	 */
	public CbcCryptor(byte[] key, byte[] iv) {
		super(key, iv);
	}


	public CbcCryptor(CryptData data) {
		this(data.getKey(), data.getIv());
	}
	


	


	


	/**
	 * CBCで暗号化
	 * @param data 暗号化する文字
	 * @return 暗号化されたデータ
	 */
	public byte[] encrypt(String data) {
		return encrypt(data, CryptConstants.UTF8);
	}
	
	
	/**
	 * CBCで暗号化
	 * @param data 暗号化する文字
	 * @param encode エンコード
	 * @return 暗号化されたデータ
	 */
	public byte[] encrypt(String data, String encode) {
		try {
			byte[] src = data.getBytes(encode);
			return encrypt(src);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
			throw new CryptException(String.format("encode[%s] is not supported.", encode), e);
		}
	}
	
	
	/**
	 * CBCで暗号化
	 * @param data 暗号化するデータ
	 * @return 暗号化されたデータ
	 */
	public byte[] encrypt(byte[] data) {
		
		try {
			Cipher cipher = Cipher.getInstance(CBC);
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
	
	
	/**
	 * CBCで復元
	 * @param data 復元するデータ
	 * @return 復元されたデータ
	 */
	public byte[] decrypt(byte[] data) {
		try {

			Cipher cipher = Cipher.getInstance(CBC);
			cipher.init(Cipher.DECRYPT_MODE, getKey(), new IvParameterSpec(getIv()));
			return cipher.doFinal(data);
		} catch (Exception e) {
			throw new CryptException("data could not be decrypted CBC", e);
		}
	}
	
	
	/**
	 * CBCで復元して文字列で返す
	 * @param data 復元するデータ
	 * @return 復元されたデータの文字列
	 */
	public String decryptString(byte[] data) {
		return decryptString(data, CryptConstants.UTF8);
	}
	
	/**
	 * CBCで復元して文字列で返す
	 * @param data 復元するデータ
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
	 * @param bitLength bitの長さ
	 * @return ランダムキー
	 */
	public static Key generateRandomKey(int bitLength) {
		return new SecretKeySpec(generateRandomBytes(bitLength), "AES");
	}
}
