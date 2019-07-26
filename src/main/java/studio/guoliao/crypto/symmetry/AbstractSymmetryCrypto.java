package studio.guoliao.crypto.symmetry;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import studio.guoliao.crypto.Crypto;
import studio.guoliao.crypto.ProviderHolder;

import java.security.Key;
import java.security.Provider;

/**
 * User: guoliao
 * Date: 2019/7/26
 * Time: 下午4:46
 * Description:
 */
public abstract class AbstractSymmetryCrypto implements Crypto {

    public static final Logger LOGGER = LoggerFactory.getLogger(AbstractSymmetryCrypto.class);

    protected Provider provider = ProviderHolder.PROVIDER;

    @Override
    public String encryptToBase64(Key key, byte[] data) {
        byte[] buf = encrypt(key, data);
        return Base64.encodeBase64String(buf);
    }

    @Override
    public String encryptToHex(Key key, byte[] data) {
        byte[] buf = encrypt(key, data);
        return Hex.encodeHexString(buf);
    }

    @Override
    public byte[] decryptFromBase64(Key key, String encryptedData) {
        byte[] buf = Base64.decodeBase64(encryptedData);
        return decrypt(key, buf);
    }

    @Override
    public byte[] decryptFromHex(Key key, String encryptedData) throws DecoderException {
        byte[] buf = Hex.decodeHex(encryptedData.toCharArray());
        return decrypt(key, buf);
    }

    @Override
    public void setProvider(Provider provider) {
        this.provider = provider;
    }
}
