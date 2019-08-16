package studio.guoliao;

import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Test;
import studio.guoliao.crypto.constant.PaddingEnum;
import studio.guoliao.crypto.symmetry.CBCCrypto;
import studio.guoliao.crypto.model.KeyDescription;
import studio.guoliao.crypto.util.KeyUtil;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * User: guoliao
 * Date: 2019/7/25
 * Time: 下午2:37
 * Description: des iv 大小为8字节
 *  aes 需要16字节的iv
 */
public class CBCTest {

    @Test
    public void desP5Test() throws NoSuchAlgorithmException {
        String val = "hellowrold";
        String iv = "12345678";
        testImpl(val, KeyDescription.DES_56, PaddingEnum.P5_PADDING, iv.getBytes());
    }

    @Test
    public void desNoPaddingTest() throws NoSuchAlgorithmException {
        String value = "helloworldhelloworldhelloworldhelloworldhelloworldhelloworld1234";
        String iv = "12345678";
        testImpl(value, KeyDescription.DES_56, PaddingEnum.NO_PADDING, iv.getBytes());
    }

    @Test
    public void desP7PaddingTest() throws NoSuchAlgorithmException {
        String val = "hellowrold";
        String iv = "12345678";
        testImpl(val, KeyDescription.DES_56, PaddingEnum.P7_PADDING, iv.getBytes());
    }

    @Test
    public void desedeNoPaddingTest() throws NoSuchAlgorithmException {
        String val = "helloworldhelloworldhelloworldhelloworldhelloworldhelloworld1234";
        String iv = "12345678";
        testImpl(val,
                KeyDescription.DESede_168, PaddingEnum.NO_PADDING, iv.getBytes());
    }

    @Test
    public void desedeP5PaddingTest() throws NoSuchAlgorithmException {
        String iv = "12345678";
        String val = "hellowrold";
        testImpl(val, KeyDescription.DESede_168, PaddingEnum.P5_PADDING, iv.getBytes());
    }

    @Test
    public void desedeP7PaddingTest() throws NoSuchAlgorithmException {
        String val = "hellowrold";
        String iv = "12345678";
        testImpl(val, KeyDescription.DESede_168, PaddingEnum.P7_PADDING, iv.getBytes());
    }

    @Test
    public void aesP7PaddingTest() throws NoSuchAlgorithmException {
        String val = "hellowrold";
        String iv = "1234567812345678";
        testImpl(val, KeyDescription.AES_128, PaddingEnum.P7_PADDING, iv.getBytes());
    }

    @Test
    public void aesNoPaddingTest() throws NoSuchAlgorithmException {
        String val = "0123456789abcdef";
        String iv = "1234567812345678";
        testImpl(val, KeyDescription.AES_128, PaddingEnum.NO_PADDING, iv.getBytes());
    }

    @Test
    public void aesP5PaddingTest() throws NoSuchAlgorithmException {
        String val = "1234567812345678";
        String iv = "1234567812345678";
        testImpl(val, KeyDescription.AES_128, PaddingEnum.P5_PADDING, iv.getBytes());
    }

    private void testImpl(String data, KeyDescription keyDescription, PaddingEnum padding, byte[] iv) throws NoSuchAlgorithmException {
        byte[] plain = data.getBytes();
        SecretKey key = KeyUtil.generateRandomKey(keyDescription);
        System.out.println(key.getAlgorithm());
        CBCCrypto crypto = new CBCCrypto(key, padding, iv);
        byte[] encrypted = crypto.encrypt(plain);
        Base64 base64 = new Base64();
        String val = base64.encodeToString(encrypted);
        System.out.println(val);
        byte[] decrypt = crypto.decrypt(encrypted);
        Assert.assertTrue(Arrays.equals(plain, decrypt));
    }
}
