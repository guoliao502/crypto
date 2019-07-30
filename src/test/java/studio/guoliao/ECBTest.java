package studio.guoliao;

import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Test;
import studio.guoliao.crypto.constant.PaddingEnum;
import studio.guoliao.crypto.symmetry.ECBCrypto;
import studio.guoliao.crypto.model.KeyDescription;
import studio.guoliao.crypto.util.KeyUtil;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * User: guoliao
 * Date: 2019/7/25
 * Time: 上午10:19
 * Description:
 */
public class ECBTest {

    @Test
    public void desP5Test() throws NoSuchAlgorithmException {
        testImpl("hellowrold", KeyDescription.DES_56, PaddingEnum.P5_PADDING);
    }

    @Test
    public void desNoPaddingTest() throws NoSuchAlgorithmException {
        testImpl("12345678", KeyDescription.DES_56, PaddingEnum.NO_PADDING);
    }

    @Test
    public void desP7PaddingTest() throws NoSuchAlgorithmException {
        testImpl("hellowrold", KeyDescription.DES_56, PaddingEnum.P7_PADDING);
    }

    @Test
    public void desedeNoPaddingTest() throws NoSuchAlgorithmException {
        testImpl("12345678",
                KeyDescription.DESede_168, PaddingEnum.NO_PADDING);
    }

    @Test
    public void desedeP5PaddingTest() throws NoSuchAlgorithmException {
        testImpl("hellowrold", KeyDescription.DESede_168, PaddingEnum.P5_PADDING);
    }

    @Test
    public void desedeP7PaddingTest() throws NoSuchAlgorithmException {
        testImpl("hellowrold", KeyDescription.DESede_168, PaddingEnum.P7_PADDING);
    }

    @Test
    public void aesP7PaddingTest() throws NoSuchAlgorithmException {
        testImpl("hellowrold", KeyDescription.AES_128, PaddingEnum.P7_PADDING);
    }

    @Test
    public void aesNoPaddingTest() throws NoSuchAlgorithmException {
        testImpl("helloworldhelloworldhelloworldhelloworldhelloworldhelloworld1234",
                KeyDescription.AES_128, PaddingEnum.NO_PADDING);
    }

    @Test
    public void aesP5PaddingTest() throws NoSuchAlgorithmException {
        testImpl("hellowrold", KeyDescription.AES_128, PaddingEnum.P5_PADDING);
    }

    private void testImpl(String data, KeyDescription keyDescription, PaddingEnum padding) throws NoSuchAlgorithmException {
        byte[] plain = data.getBytes();
        SecretKey key = KeyUtil.generateRandomKey(keyDescription);
        System.out.println(key.getAlgorithm());
        ECBCrypto crypto = new ECBCrypto(padding);
        byte[] encrypted = crypto.encrypt(key, plain);
        Base64 base64 = new Base64();
        String val = base64.encodeToString(encrypted);
        System.out.println(val);
        byte[] decrypt = crypto.decrypt(key, encrypted);
        Assert.assertTrue(Arrays.equals(plain, decrypt));
    }
}
