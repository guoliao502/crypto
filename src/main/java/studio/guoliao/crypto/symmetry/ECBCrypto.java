package studio.guoliao.crypto.symmetry;

import studio.guoliao.crypto.constant.PaddingEnum;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * User: guoliao
 * Date: 2019/7/23
 * Time: 下午5:35
 * Description: ecb加密模式
 *  如果需要使用nopadding模式，需要数据长度为64的整数倍
 *  默认使用pkcs5padding
 */
public class ECBCrypto extends AbstractSymmetryCrypto{

    private static final String FMT = "%s/ECB/%s";

    private String padding;

    public ECBCrypto(Key key){
        this(key, PaddingEnum.P5_PADDING);
    }

    public ECBCrypto(Key key, PaddingEnum padding) {
        this(key, padding.getValue());
    }

    public ECBCrypto(Key key, String padding) {
        this.padding = padding;
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
            cipher.init(mode, key);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException |
                NoSuchPaddingException | BadPaddingException |
                IllegalBlockSizeException e) {
            System.out.println(e);
        }
        return null;
    }

    private String dealAlg(String alg){
        return (padding == null || padding.isEmpty()) ? alg : String.format(FMT, alg, padding);
    }
}
