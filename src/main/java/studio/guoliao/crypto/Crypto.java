package studio.guoliao.crypto;

import java.security.Key;

/**
 * User: guoliao
 * Date: 2019/7/23
 * Time: 下午5:30
 * Description: 加密接口
 */
public interface Crypto extends ProviderHolder {

    byte[] encrypt(Key key, byte[] data);

    byte[] decrypt(Key key, byte[] encryptedData);
}
