package studio.guoliao;

import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Test;
import studio.guoliao.crypto.constant.PBEAlgEnum;
import studio.guoliao.crypto.symmetry.PBECrypto;
import studio.guoliao.crypto.util.KeyUtil;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * User: guoliao
 * Date: 2019/7/25
 * Time: 下午3:17
 * Description:
 */
public class PBETest {

    @Test
    public void des() throws InvalidKeySpecException, NoSuchAlgorithmException {
        impl(PBEAlgEnum.MD5_DES);
    }

    @Test
    public void sha1() throws InvalidKeySpecException, NoSuchAlgorithmException {
        impl(PBEAlgEnum.SHA1_DES);
    }

    @Test
    public void sha1Desede() throws InvalidKeySpecException, NoSuchAlgorithmException {
        impl(PBEAlgEnum.SHA1_DESEDE);
    }

    @Test
    public void sha1Aes() throws InvalidKeySpecException, NoSuchAlgorithmException {
        impl(PBEAlgEnum.SHA1_AES128_CBC);
    }

    @Test
    public void sha2Aes() throws InvalidKeySpecException, NoSuchAlgorithmException {
        impl(PBEAlgEnum.SHA256_AES128_CBC);
    }

    private void impl(PBEAlgEnum alg) throws InvalidKeySpecException, NoSuchAlgorithmException {
        String password = "helloworld";
        String text = "helloworld";
        KeyUtil keyUtil = new KeyUtil();
        SecretKey key = keyUtil.generatePBEKey(alg, password);
        PBECrypto crypto = new PBECrypto(key, alg);
        byte[] buf = crypto.encrypt(text.getBytes());
        System.out.println(Base64.encodeBase64String(buf));
        byte[] tmp = crypto.decrypt(buf);
        String val = new String(tmp);
        Assert.assertEquals(text, val);
    }
}
