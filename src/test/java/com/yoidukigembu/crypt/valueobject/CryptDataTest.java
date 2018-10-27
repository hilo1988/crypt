package com.yoidukigembu.crypt.valueobject;

import com.yoidukigembu.crypt.aes.CbcCryptor;
import junit.framework.TestCase;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CryptDataTest extends TestCase {

    private static final String STR = "sfdafkjas;dlflzd;zlsdn;falksdn;asdknf;la";

    @Test
    public void test() {
        final CryptData data = CryptData.newInstance(128);

        final CbcCryptor cbc1 = new CbcCryptor(data);

        final byte[] encrypted = cbc1.encrypt(STR);

        assertEquals(STR, cbc1.decryptString(encrypted));

        final CbcCryptor cbc2 = new CbcCryptor(new CryptData(data.getKey(), data.getIv()));

        for (int i = 0; i < cbc1.getIv().length; i++) {
            assertEquals(cbc1.getIv()[i], cbc2.getIv()[i]);
        }

        final String str = cbc2.decryptString(encrypted);

        assertEquals(STR, str);

    }
}
