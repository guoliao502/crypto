package studio.guoliao.crypto.asymmetry;


import studio.guoliao.crypto.Crypto;

import java.security.Key;

/**
 * User: guoliao
 * Date: 2019/7/23
 * Time: 下午6:06
 * Description:
 */
public class CommonCrypto implements Crypto {

    @Override
    public byte[] encrypt(Key key, byte[] data) {
        return new byte[0];
    }

    @Override
    public byte[] decrypt(Key key, byte[] encryptedData) {
        return new byte[0];
    }
}
