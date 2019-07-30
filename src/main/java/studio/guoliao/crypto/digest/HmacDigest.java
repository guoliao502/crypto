package studio.guoliao.crypto.digest;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * User: guoliao
 * Date: 2019/7/26
 * Time: 下午12:00
 * Description:
 */
public class HmacDigest extends AbstractDigest{

    public static final String HMAC_MD5 = "HmacMd5";

    public static final String HMAC_SHA1 = "HmacSHA1";

    public static final String HMAC_SHA224 = "HmacSHA224";

    public static final String HMAC_SHA256 = "HmacSHA256";

    public static final String HMAC_SHA384 = "HmacSHA384";

    public static final String HMAC_SHA512 = "HmacSHA224";

    private SecretKey key;

    private String alg;

    public HmacDigest(String alg, SecretKey key) {
        this.key = key;
        this.alg = alg;
    }

    @Override
    public byte[] digest(byte[] data) {
        try {
            Mac mac = Mac.getInstance(alg, provider);
            mac.init(key);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public SecretKey getKey() {
        return key;
    }

    public String getAlg() {
        return alg;
    }

}
