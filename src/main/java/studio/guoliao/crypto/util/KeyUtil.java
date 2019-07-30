package studio.guoliao.crypto.util;

import studio.guoliao.crypto.ProviderHolder;
import studio.guoliao.crypto.constant.PBEAlgEnum;
import studio.guoliao.crypto.model.KeyDescription;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;

/**
 * User: guoliao
 * Date: 2019/7/23
 * Time: 下午6:08
 * Description: 提供常见的密钥操作
 */
public class KeyUtil {

    /**
     * 根据指定算法、长度、随记数种子产生一个固定密钥
     * @param randomAlg 随机器算法
     * @param randomSeed 随机数种子
     * @see KeyDescription
     * */
    public static SecretKey generateSameKey(KeyDescription keyDescription, String randomAlg, byte[] randomSeed) throws NoSuchAlgorithmException {
        return generateSameKey(keyDescription, randomAlg, randomSeed, ProviderHolder.PROVIDER);
    }

    /**
     * 根据指定算法、长度、随记数种子产生一个固定密钥
     * @param randomAlg 随机器算法
     * @param randomSeed 随机数种子
     * @see KeyDescription
     * */
    public static SecretKey generateSameKey(KeyDescription keyDescription,
                                            String randomAlg, byte[] randomSeed, 
                                            Provider provider) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstance(randomAlg);
        secureRandom.setSeed(randomSeed);
        KeyGenerator generator = KeyGenerator.getInstance(keyDescription.getAlg(), provider);
        generator.init(secureRandom);
        return generator.generateKey();
    }

    /**
     * 根据指定算法、长度产生一个随机密钥
     * @see KeyDescription
     * */
    public static SecretKey generateRandomKey(KeyDescription keyDescription) throws NoSuchAlgorithmException {
        return generateRandomKey(keyDescription, ProviderHolder.PROVIDER);
    }

    /**
     * 根据指定算法、长度产生一个随机密钥
     * @see KeyDescription
     * */
    public static SecretKey generateRandomKey(KeyDescription keyDescription, 
                                              Provider provider) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator generator = KeyGenerator.getInstance(keyDescription.getAlg(), provider);
        generator.init(secureRandom);
        return generator.generateKey();
    }

    /**
     * 根据指定算法、长度、随记数种子产生一个随机密钥
     * @param randomSeed 随机数种子
     * @see KeyDescription
     * */
    public static SecretKey generateRandomKey(KeyDescription keyDescription, byte[] randomSeed) throws NoSuchAlgorithmException {
        return generateRandomKey(keyDescription, randomSeed, ProviderHolder.PROVIDER);
    }

    /**
     * 根据指定算法、长度、随记数种子产生一个随机密钥
     * @param randomSeed 随机数种子
     * @see KeyDescription
     * */
    public static SecretKey generateRandomKey(KeyDescription keyDescription, byte[] randomSeed, 
                                              Provider provider) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed(randomSeed);
        KeyGenerator generator = KeyGenerator.getInstance(keyDescription.getAlg(), provider);
        generator.init(secureRandom);
        return generator.generateKey();
    }


    /**
     * 根据指定算法和密钥的byte[] 恢复出密钥
     * @param description
     * @param key 使用byte[]表示的密钥
     * @see KeyDescription*/
    public static SecretKey generateKeyFromByteArr(KeyDescription description, byte[] key){
        return new SecretKeySpec(key, description.getAlg());
    }

    /**
     * 产生一个pbe模式的密钥*/
    public static SecretKey generatePBEKey(PBEAlgEnum alg, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return generatePBEKey(alg, password, ProviderHolder.PROVIDER);
    }

    /**
     * 产生一个pbe模式的密钥*/
    public static SecretKey generatePBEKey(PBEAlgEnum alg, String password, Provider provider) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance(alg.getValue(), provider);
        return keyFac.generateSecret(pbeKeySpec);
    }

    /**
     * 产生一个pbe模式的密钥*/
    public static SecretKey generatePBEKey(String alg, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance(alg, ProviderHolder.PROVIDER);
        return keyFac.generateSecret(pbeKeySpec);
    }

    /**
     * 产生一个pbe模式的密钥*/
    public static SecretKey generatePBEKey(String alg, String password, Provider provider) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance(alg, provider);
        return keyFac.generateSecret(pbeKeySpec);
    }

    /**
     * 从x509中获取公钥*/
    public static PublicKey generatePublicKeyFromX509(byte[] buf) throws IOException, NoSuchAlgorithmException, CertificateException {
        PublicKey key = null;
        String type = "X.509";
        try(InputStream in = new ByteArrayInputStream(buf)){
            key = generatePublicKeyFromX509(type, in);
        }
        return key;
    }

    /**
     * 从x509文件中获取公钥*/
    public static PublicKey generatePublicKeyFromX509(File file) throws IOException, NoSuchAlgorithmException, CertificateException {
        PublicKey key = null;
        String type = "X.509";
        try(FileInputStream in = new FileInputStream(file)){
            key = generatePublicKeyFromX509(type, in);
        }
        return key;
    }

    public static KeyPair generateKeyPair(KeyDescription keyDescription) throws NoSuchAlgorithmException {
        return generateKeyPair(keyDescription, ProviderHolder.PROVIDER);
    }

    public static KeyPair generateKeyPair(KeyDescription keyDescription, Provider provider) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyDescription.getAlg(), provider);
        generator.initialize(keyDescription.getLength());
        return generator.genKeyPair();
    }

    /**
     * @param type  jks PKCS12*/
    public static KeyStore readKeyStore(String type, InputStream in, String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(type, ProviderHolder.PROVIDER);
        if(password == null){
            keyStore.load(in, null);
        }else{
            keyStore.load(in, password.toCharArray());
        }
        return keyStore;
    }

    private static PublicKey generatePublicKeyFromX509(String alg, InputStream in) throws IOException, NoSuchAlgorithmException, CertificateException {
        PublicKey key = null;
        CertificateFactory factory = CertificateFactory.getInstance(alg, ProviderHolder.PROVIDER);
        Certificate cert = factory.generateCertificate(in);
        key = cert.getPublicKey();
        return key;
    }
}
