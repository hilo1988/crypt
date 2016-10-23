package tech.hilo.crypt.aes;

import java.security.Key;
import java.util.Random;

import javax.crypto.spec.SecretKeySpec;

/**
 * keyに関するインフォクラス
 * @author hilo
 *
 */
public abstract class BaseAes {
	
	/** キー */
	private final Key key;
	
	/** IV */
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
	
	public static byte[] generateRandomBytes(int bitLength) {
		byte[] key = new byte[bitLength / 8];
		new Random().nextBytes(key);
		return key;
	}
	
}
