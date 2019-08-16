package studio.guoliao.crypto;

import org.apache.commons.codec.DecoderException;

/**
 * User: guoliao
 * Date: 2019/7/23
 * Time: 下午5:30
 * Description: 加解密功能接口
 */
public interface Crypto extends ProviderChangeable{

    byte[] encrypt(byte[] data);

    String encryptToBase64(byte[] data);

    String encryptToHex(byte[] data);

    byte[] decrypt(byte[] encryptedData);

    byte[] decryptFromBase64(String encryptedData);

    byte[] decryptFromHex(String encryptedData) throws DecoderException;
}
