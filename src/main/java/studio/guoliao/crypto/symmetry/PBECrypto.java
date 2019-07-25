package studio.guoliao.crypto.symmetry;

import studio.guoliao.crypto.Crypto;
import studio.guoliao.crypto.Provider;
import studio.guoliao.crypto.constant.PBEAlgEnum;

import javax.crypto.*;
import javax.crypto.spec.PBEParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * User: guoliao
 * Date: 2019/7/23
 * Time: 下午6:20
 * Description:
 */
public class PBECrypto implements Crypto {

    private byte[] slat = "randomSlat".getBytes();

    private int iterationCount = 20;

    private String alg;

    public PBECrypto(PBEAlgEnum pbeAlgEnum) {
        this.alg = pbeAlgEnum.getValue();
    }

    public PBECrypto(String alg) {
        this.alg = alg;
    }

    public PBECrypto(PBEAlgEnum pbeAlg, byte[] slat, int iterationCount) {
        this.slat = slat;
        this.iterationCount = iterationCount;
        this.alg = pbeAlg.getValue();
    }

    public PBECrypto(String alg, byte[] slat, int iterationCount) {
        this.slat = slat;
        this.iterationCount = iterationCount;
        this.alg = alg;
    }

    @Override
    public byte[] encrypt(Key key, byte[] data) {
        return cryptoImpl(Cipher.ENCRYPT_MODE, key, data);
    }

    @Override
    public byte[] decrypt(Key key, byte[] encryptedData) {
        return cryptoImpl(Cipher.DECRYPT_MODE, key, encryptedData);
    }

    private byte[] cryptoImpl(int mode, Key key,  byte[] data){
        try {
            Cipher cipher = Cipher.getInstance(alg, Provider.PROVIDER);
            PBEParameterSpec parameterSpec = new PBEParameterSpec(slat, iterationCount);
            SecretKey tmp = (SecretKey) key;
            cipher.init(mode, tmp, parameterSpec);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            LOGGER.error(e.getMessage());
        }
        return null;
    }
}
