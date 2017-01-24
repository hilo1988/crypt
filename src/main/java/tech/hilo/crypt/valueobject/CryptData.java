package tech.hilo.crypt.valueobject;

import lombok.Data;
import tech.hilo.crypt.aes.CbcCryptor;

import java.io.Serializable;

/**
 * Created by hilo on 2017/01/11.
 */
@Data
public class CryptData implements Serializable {

    private static final long serialVersionUID = 9210353025268317628L;

    /** キー */
    private byte[] key;

    /** iv */
    private byte[] iv;

    public CryptData(int length) {
        CbcCryptor cbc = new CbcCryptor(length);
        // KeyとIVを発生させるため、なんでもいいのでエンコードする
        cbc.encrypt("aaa");
        this.key = cbc.getKeyBytes();
        this.iv = cbc.getIv();
    }
}
