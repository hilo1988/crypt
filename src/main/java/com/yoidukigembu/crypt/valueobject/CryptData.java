package com.yoidukigembu.crypt.valueobject;

import com.yoidukigembu.crypt.aes.CbcCryptor;
import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.io.Serializable;

/**
 * Created by hilo on 2017/01/11.
 */
@Data
@RequiredArgsConstructor
public class CryptData implements Serializable {

    private static final long serialVersionUID = 9210353025268317628L;

    /**
     * キー
     */
    private final byte[] key;

    /**
     * iv
     */
    private final byte[] iv;

    public static CryptData newInstance(int length) {
        CbcCryptor cbc = new CbcCryptor(length);
        // KeyとIVを発生させるため、なんでもいいのでエンコードする
        cbc.encrypt("aaa");

        return new CryptData(cbc.getKeyBytes(), cbc.getIv());
    }


}
