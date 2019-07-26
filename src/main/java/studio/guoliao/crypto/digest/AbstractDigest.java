package studio.guoliao.crypto.digest;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import studio.guoliao.crypto.Digest;
import studio.guoliao.crypto.ProviderHolder;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * User: guoliao
 * Date: 2019/7/26
 * Time: 下午4:54
 * Description:
 */
public abstract class AbstractDigest implements Digest {

    public static final Logger LOGGER = LoggerFactory.getLogger(AbstractDigest.class);

    protected Provider provider = ProviderHolder.PROVIDER;

    @Override
    public String digestToBase64(byte[] data) throws NoSuchAlgorithmException {
        byte[] buf = digest(data);
        return Base64.encodeBase64String(buf);
    }

    @Override
    public String digestToHex(byte[] data) throws NoSuchAlgorithmException {
        byte[] buf = digest(data);
        return Hex.encodeHexString(buf);
    }

    @Override
    public void setProvider(Provider provider) {
        this.provider = provider;
    }
}
