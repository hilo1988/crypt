package com.hilo_islay.crypt;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import junit.framework.TestCase;
import com.hilo_islay.crypt.aes.CbcCryptor;
import com.hilo_islay.crypt.exception.CryptException;

@RunWith(JUnit4.class)
public class CbcCryptorTest extends TestCase {

	@Test
	public void 暗号復元テスト() {
		final String src = "sfdafkjas;dlflzd;zlsdn;falksdn;asdknf;la";
		CbcCryptor cbc1 = new CbcCryptor(128);
		byte[] cryptedData = cbc1.encrypt(src);
		
		assertEquals(src, cbc1.decryptString(cryptedData));

		assertEquals("aaaaa", cbc1.decryptString(cbc1.encrypt("aaaaa")));
		
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
