package studio.guoliao.crypto.symmetry;

import studio.guoliao.crypto.Crypto;
import studio.guoliao.crypto.Provider;
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
 */
public class ECBCrypto implements Crypto {

    private static final String FMT = "%s/ECB/%s";

    private String padding;

    public ECBCrypto(PaddingEnum padding) {
        this.padding = padding.getValue();
    }

    public ECBCrypto(String padding) {
        this.padding = padding;
    }

    @Override
    public byte[] encrypt(Key key, byte[] data) {
        return cryptoImpl(Cipher.ENCRYPT_MODE, data, key);
    }

    @Override
    public byte[] decrypt(Key key, byte[] encryptedData) {
        return cryptoImpl(Cipher.DECRYPT_MODE, encryptedData, key);
    }

    private byte[] cryptoImpl(int mode, byte[] data, Key key){
        try {
            String alg = key.getAlgorithm();
            String algWithPadding = String.format(FMT, alg, padding);
            Cipher cipher = Cipher.getInstance(algWithPadding, Provider.PROVIDER);
            cipher.init(mode, key);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException |
                NoSuchPaddingException | BadPaddingException |
                IllegalBlockSizeException e) {
            LOGGER.error(e.getMessage());
        }
        return null;
    }
}
