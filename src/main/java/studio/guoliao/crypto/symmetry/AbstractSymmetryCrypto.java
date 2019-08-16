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

    static final Logger LOGGER = LoggerFactory.getLogger(AbstractSymmetryCrypto.class);

    protected Provider provider = ProviderHolder.PROVIDER;

    protected Key key;

    @Override
    public String encryptToBase64(byte[] data) {
        byte[] buf = encrypt(data);
        return Base64.encodeBase64String(buf);
    }

    @Override
    public String encryptToHex(byte[] data) {
        byte[] buf = encrypt(data);
        return Hex.encodeHexString(buf);
    }

    @Override
    public byte[] decryptFromBase64(String encryptedData) {
        byte[] buf = Base64.decodeBase64(encryptedData);
        return decrypt(buf);
    }

    @Override
    public byte[] decryptFromHex(String encryptedData) throws DecoderException {
        byte[] buf = Hex.decodeHex(encryptedData.toCharArray());
        return decrypt(buf);
    }

    @Override
    public void setProvider(Provider provider) {
        this.provider = provider;
    }
}
