package studio.guoliao.crypto;

import org.apache.commons.codec.DecoderException;

import java.security.Key;

/**
 * User: guoliao
 * Date: 2019/7/23
 * Time: 下午5:30
 * Description: 加解密功能接口
 */
public interface Crypto extends ProviderHolder {

    byte[] encrypt(Key key, byte[] data);

    String encryptToBase64(Key key, byte[] data);

    String encryptToHex(Key key, byte[] data);

    byte[] decrypt(Key key, byte[] encryptedData);

    byte[] decryptFromBase64(Key key, String encryptedData);

    byte[] decryptFromHex(Key key, String encryptedData) throws DecoderException;
}
