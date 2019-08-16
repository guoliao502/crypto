package studio.guoliao.crypto.symmetry;

import studio.guoliao.crypto.constant.PaddingEnum;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * User: guoliao
 * Date: 2019/7/23
 * Time: 下午5:50
 * Description: cbc加密模式
 *  设置iv时，需要注意iv的长度
 *      des 8字节长度
 *      aes 16字节长度
 */
public class CBCCrypto extends AbstractSymmetryCrypto {

    private static final String FMT = "%s/CBC/%s";

    private String padding;

    private byte[] iv;

    public CBCCrypto(Key key, byte[] iv) {
        this(key, PaddingEnum.P5_PADDING, iv);
    }

    public CBCCrypto(Key key, PaddingEnum paddingEnum, byte[] iv) {
        this(key, paddingEnum.getValue(), iv);
    }

    public CBCCrypto(Key key, String padding, byte[] iv) {
        super();
        this.padding = padding;
        this.iv = iv;
        this.key = key;
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return cryptoImpl(Cipher.ENCRYPT_MODE, data, key);
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) {
        return cryptoImpl(Cipher.DECRYPT_MODE, encryptedData, key);
    }

    private byte[] cryptoImpl(int mode, byte[] data, Key key){
        try {
            String alg = key.getAlgorithm();
            String algWithPadding = dealAlg(alg);
            Cipher cipher = Cipher.getInstance(algWithPadding, providerHolder.getProvider());
            cipher.init(mode, key, new IvParameterSpec(iv));
            return cipher.doFinal(data);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                NoSuchPaddingException | NoSuchAlgorithmException |
                BadPaddingException | IllegalBlockSizeException e) {
            System.out.println(e);
        }
        return null;
    }

    private String dealAlg(String alg){
        return (padding == null || padding.isEmpty()) ? alg : String.format(FMT, alg, padding);
    }
}
