package studio.guoliao;

import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Test;
import studio.guoliao.crypto.digest.CommonDigest;
import studio.guoliao.crypto.digest.HmacDigest;
import studio.guoliao.crypto.model.KeyDescription;
import studio.guoliao.crypto.util.KeyUtil;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * User: guoliao
 * Date: 2019/7/26
 * Time: 下午2:46
 * Description:
 */
public class DigestTest {

    @Test
    public void digest(){
        String data = "helloworld";
        byte[] tmp = CommonDigest.MD5_DIGEST.digest(data.getBytes());
        System.out.println(Base64.encodeBase64String(tmp));
        tmp = CommonDigest.SHA1_DIGEST.digest(data.getBytes());
        System.out.println(Base64.encodeBase64String(tmp));
        tmp = CommonDigest.SHA224_DIGEST.digest(data.getBytes());
        System.out.println(Base64.encodeBase64String(tmp));
        tmp = CommonDigest.SHA256_DIGEST.digest(data.getBytes());
        System.out.println(Base64.encodeBase64String(tmp));
        tmp = CommonDigest.SHA512_DIGEST.digest(data.getBytes());
        System.out.println(Base64.encodeBase64String(tmp));
    }

    @Test
    public void hmacDigest() throws InvalidKeySpecException, NoSuchAlgorithmException {
        String data = "helloworld";
        SecretKey key = KeyUtil.generateSameKey(KeyDescription.DES_56, "SHA1PRNG", data.getBytes());
        HmacDigest digest = new HmacDigest(HmacDigest.HMAC_MD5, key);
        byte[] buf = digest.digest(data.getBytes());
        System.out.println(Base64.encodeBase64String(buf));
        Assert.assertNotNull("", buf);
    }
}
