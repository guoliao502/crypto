package studio.guoliao.crypto.digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * User: guoliao
 * Date: 2019/7/23
 * Time: 下午6:01
 * Description:
 */
public class CommonDigest extends AbstractDigest{

    public static final CommonDigest MD5_DIGEST = new CommonDigest("MD5");

    public static final CommonDigest SHA1_DIGEST = new CommonDigest("SHA1");

    public static final CommonDigest SHA224_DIGEST = new CommonDigest("SHA224");

    public static final CommonDigest SHA256_DIGEST = new CommonDigest("SHA256");

    public static final CommonDigest SHA512_DIGEST = new CommonDigest("SHA512");

    private String alg;

    public CommonDigest(String alg) {
        super();
        this.alg = alg;
    }

    @Override
    public byte[] digest(byte[] data) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(alg, provider);
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
}
