package studio.guoliao;

import org.junit.Assert;
import org.junit.Test;
import studio.guoliao.crypto.ProviderHolder;
import studio.guoliao.crypto.model.KeyDescription;
import studio.guoliao.crypto.util.KeyUtil;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * User: guoliao
 * Date: 2019/7/29
 * Time: 下午3:31
 * Description:
 */
public class KeyUtilTest {

    @Test
    public void genSameKey() throws NoSuchAlgorithmException {
        SecretKey key1 = KeyUtil.generateSameKey(KeyDescription.DES_56, "SHA1PRNG", "helloworld".getBytes());
        SecretKey keyw = KeyUtil.generateSameKey(KeyDescription.DES_56, "SHA1PRNG", "helloworld".getBytes(), ProviderHolder.PROVIDER);
        byte[] buf = key1.getEncoded();
        byte[] buf2 = keyw.getEncoded();
        boolean result = Arrays.equals(buf, buf2);
        Assert.assertTrue(result);
    }
}
