package studio.guoliao.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import studio.guoliao.crypto.symmetry.ECBCrypto;

import java.security.Key;

/**
 * User: guoliao
 * Date: 2019/7/23
 * Time: 下午5:30
 * Description: 加密接口
 */
public interface Crypto {

    Logger LOGGER = LoggerFactory.getLogger(ECBCrypto.class);

    byte[] encrypt(Key key, byte[] data);

    byte[] decrypt(Key key, byte[] encryptedData);
}
