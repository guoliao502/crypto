package studio.guoliao.crypto.util;

import studio.guoliao.crypto.ProviderChangeable;
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
public class KeyUtil implements ProviderChangeable {

    private ProviderHolder providerHolder = ProviderHolder.newInstance();

    public KeyUtil() {
    }

    public KeyUtil(ProviderHolder providerHolder) {
        this.providerHolder = providerHolder;
    }

    /**
     * 根据指定算法、长度、随记数种子产生一个固定密钥
     * @param randomAlg 随机器算法
     * @param randomSeed 随机数种子
     * @see KeyDescription
     * */
    public SecretKey generateSameKey(KeyDescription keyDescription,
                                            String randomAlg, byte[] randomSeed) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstance(randomAlg);
        secureRandom.setSeed(randomSeed);
        KeyGenerator generator = KeyGenerator.getInstance(keyDescription.getAlg());
        generator.init(secureRandom);
        return generator.generateKey();
    }

    /**
     * 根据指定算法、长度产生一个随机密钥
     * @see KeyDescription
     * */
    public SecretKey generateRandomKey(KeyDescription keyDescription) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator generator = KeyGenerator.getInstance(keyDescription.getAlg(), providerHolder.getProvider());
        generator.init(secureRandom);
        return generator.generateKey();
    }

    /**
     * 根据指定算法、长度、随记数种子产生一个随机密钥
     * @param randomSeed 随机数种子
     * @see KeyDescription
     * */
    public SecretKey generateRandomKey(KeyDescription keyDescription, byte[] randomSeed) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed(randomSeed);
        KeyGenerator generator = KeyGenerator.getInstance(keyDescription.getAlg(), providerHolder.getProvider());
        generator.init(secureRandom);
        return generator.generateKey();
    }


    /**
     * 根据指定算法和密钥的byte[] 恢复出密钥
     * @param description
     * @param key 使用byte[]表示的密钥
     * @see KeyDescription*/
    public SecretKey generateKeyFromByteArr(KeyDescription description, byte[] key){
        return new SecretKeySpec(key, description.getAlg());
    }

    /**
     * 产生一个pbe模式的密钥*/
    public SecretKey generatePBEKey(PBEAlgEnum alg, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return this.generatePBEKey(alg.getValue(), password);
    }

    /**
     * 产生一个pbe模式的密钥*/
    public SecretKey generatePBEKey(String alg, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance(alg, providerHolder.getProvider());
        return keyFac.generateSecret(pbeKeySpec);
    }

    /**
     * 从x509中获取公钥*/
    public PublicKey generatePublicKeyFromX509(byte[] buf) throws IOException, NoSuchAlgorithmException, CertificateException {
        PublicKey key = null;
        String type = "X.509";
        try(InputStream in = new ByteArrayInputStream(buf)){
            key = generatePublicKeyFromX509(type, in);
        }
        return key;
    }

    /**
     * 从x509文件中获取公钥*/
    public PublicKey generatePublicKeyFromX509(File file) throws IOException, NoSuchAlgorithmException, CertificateException {
        PublicKey key = null;
        String type = "X.509";
        try(FileInputStream in = new FileInputStream(file)){
            key = generatePublicKeyFromX509(type, in);
        }
        return key;
    }

    public KeyPair generateKeyPair(KeyDescription keyDescription) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyDescription.getAlg(), providerHolder.getProvider());
        generator.initialize(keyDescription.getLength());
        return generator.genKeyPair();
    }

    /**
     * @param type  jks PKCS12*/
    public KeyStore readKeyStore(String type, InputStream in, String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(type, providerHolder.PROVIDER);
        if(password == null){
            keyStore.load(in, null);
        }else{
            keyStore.load(in, password.toCharArray());
        }
        return keyStore;
    }

    private PublicKey generatePublicKeyFromX509(String alg, InputStream in) throws IOException, NoSuchAlgorithmException, CertificateException {
        PublicKey key = null;
        CertificateFactory factory = CertificateFactory.getInstance(alg, providerHolder.getProvider());
        Certificate cert = factory.generateCertificate(in);
        key = cert.getPublicKey();
        return key;
    }

    @Override
    public void setProviderHolder(ProviderHolder providerHolder) {
        this.providerHolder = providerHolder;
    }
}
