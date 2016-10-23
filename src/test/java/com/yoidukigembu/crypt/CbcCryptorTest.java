package com.yoidukigembu.crypt;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import junit.framework.TestCase;
import tech.hilo.crypt.aes.CbcCryptor;
import tech.hilo.crypt.exception.CryptException;

@RunWith(JUnit4.class)
public class CbcCryptorTest extends TestCase {

	@Test
	public void 暗号復元テスト() {
		String src = "テストです。";
		CbcCryptor cbc1 = new CbcCryptor(128);
		byte[] cryptedData = cbc1.encrypt(src);
		
		assertEquals(src, cbc1.decryptString(cryptedData));
		
		CbcCryptor cbc2 = new CbcCryptor(cbc1.getKey(), cbc1.getIv());
		assertEquals(src, cbc2.decryptString(cryptedData));
		
		
		CbcCryptor failCbc1 = new CbcCryptor(128);
		try {
			failCbc1.decrypt(cryptedData);
			fail();
		} catch (CryptException e) {
			
		}
		
		failCbc1.setIv(cbc1.getIv());
		
		try {
			failCbc1.decrypt(cryptedData);
			fail();
		} catch (CryptException e) {
			
		}
		
		CbcCryptor failCbc2 = new CbcCryptor(cbc1.getKey());
		try {
			failCbc2.decrypt(cryptedData);
			fail();
		} catch (CryptException e) {
			
		}
		
		failCbc2.setIv("abc".getBytes());
		try {
			failCbc2.decrypt(cryptedData);
			fail();
		} catch (CryptException e) {
			
		}
	}

}
