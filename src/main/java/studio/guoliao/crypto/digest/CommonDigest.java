package studio.guoliao.crypto.digest;

import studio.guoliao.crypto.Digest;
import studio.guoliao.crypto.ProviderHolder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * User: guoliao
 * Date: 2019/7/23
 * Time: 下午6:01
 * Description:
 */
public class CommonDigest implements Digest {

    public static final CommonDigest MD5_DIGEST = new CommonDigest("MD5");

    public static final CommonDigest SHA1_DIGEST = new CommonDigest("SHA1");

    public static final CommonDigest SHA224_DIGEST = new CommonDigest("SHA224");

    public static final CommonDigest SHA256_DIGEST = new CommonDigest("SHA256");

    public static final CommonDigest SHA512_DIGEST = new CommonDigest("SHA512");

    private String alg;

    private Provider provider = PROVIDER;

    public CommonDigest(String alg) {
        this.alg = alg;
    }

    @Override
    public byte[] digest(byte[] data) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(alg, ProviderHolder.PROVIDER);
            messageDigest.update(data);
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error(e.getMessage());
        }
        return null;
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    @Override
    public void setProvider(Provider provider) {
        this.provider = provider;
    }
}
