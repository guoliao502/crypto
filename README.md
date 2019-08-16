## easy to use java crypto api 
* default use bouncy castle provider
* users can custom provider
* support common hash、symmetry algorithm（asymmetry coming soon）
## api description
* generate secret key (use KeyUtil.class)
* you can set ProviderHolder field change provider implement and use ProviderHolder.setProvider method change provider
```java
public class KeyUtil {

    /**
         * 根据指定算法、长度、随记数种子产生一个固定密钥
         * @param randomAlg 随机器算法
         * @param randomSeed 随机数种子
         * @see KeyDescription
         * */
        public SecretKey generateSameKey(KeyDescription keyDescription, String randomAlg, byte[] randomSeed) throws NoSuchAlgorithmException ;
    
        /**
         * 根据指定算法、长度产生一个随机密钥
         * @see KeyDescription
         * */
        public SecretKey generateRandomKey(KeyDescription keyDescription) throws NoSuchAlgorithmException ;
    
        /**
         * 根据指定算法、长度、随记数种子产生一个随机密钥
         * @param randomSeed 随机数种子
         * @see KeyDescription
         * */
        public SecretKey generateRandomKey(KeyDescription keyDescription, byte[] randomSeed) throws NoSuchAlgorithmException;
    
    
        /**
         * 根据指定算法和密钥的byte[] 恢复出密钥
         * @param description
         * @param key 使用byte[]表示的密钥
         * @see KeyDescription*/
        public SecretKey generateKeyFromByteArr(KeyDescription description, byte[] key);
    
        /**
         * 产生一个pbe模式的密钥*/
        public SecretKey generatePBEKey(PBEAlgEnum alg, String password) throws NoSuchAlgorithmException, InvalidKeySpecException ;
    
        /**
         * 产生一个pbe模式的密钥*/
        public SecretKey generatePBEKey(String alg, String password) throws NoSuchAlgorithmException, InvalidKeySpecException ;
    
        /**
         * 从x509中获取公钥*/
        public PublicKey generatePublicKeyFromX509(byte[] buf) throws IOException, NoSuchAlgorithmException, CertificateException ;
    
        /**
         * 从x509文件中获取公钥*/
        public PublicKey generatePublicKeyFromX509(File file) throws IOException, NoSuchAlgorithmException, CertificateException;
    
        public KeyPair generateKeyPair(KeyDescription keyDescription) throws NoSuchAlgorithmException;
    
        /**
         * @param type  jks PKCS12*/
        public KeyStore readKeyStore(String type, InputStream in, String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException ;
}
```
* symmetry crypto api
```
public byte[] encrypt(byte[] buf);
public String encryptToBase64(byte[] buf);
public String encryptToHex(byte[] buf);
public byte[] decryptFromBase64(String encryptedData);
public byte[] decryptFromHex(String encryptedData);
```
* hash api
```
public String digestToBase64(byte[] data) throws NoSuchAlgorithmException ;
public String digestToHex(byte[] data) throws NoSuchAlgorithmException ;
public byte[] digest(byte[] data) throws NoSuchAlgorithmException ;
```

### use case
* crypto 
```java
/**
* if you want use no_padding in des, you plainText should be n*64 bit; 
* in aes you should make sure you data be n*128bit
* @see studio.guoliao.crypto.constant.PaddingEnum
* */
public class Test{
    public static void main(String[] args){
        String plain = "helloworld";
        studio.guoliao.crypto.util.KeyUtil keyUtil = new studio.guoliao.crypto.util.KeyUtil();
        SecretKey key = keyUtil.generateRandomKey(KeyDescription.DES_56);
        ECBCrypto crypto = new ECBCrypto(PaddingEnum.P5_PADDING);
        byte[] encrypted = crypto.encrypt(key, plain);
        byte[] tmp = crypto.decrypt(key, encrypted);
        //...
        byte[] iv = "".getBytes();
        CBCCrypto crypto = new CBCCrypto(PaddingEnum.P5_PADDING, iv);
        byte[] encrypted = crypto.encrypt(key, plain);
        byte[] val = crypto.encrypt(key, encrypted);
    }
}
```
* digest
```java
public class Test{
    public static void main(String[] args){
        String data = "helloworld";
        CommonDigest.MD5_DIGEST.digest(data.getBytes());
        CommonDigest.SHA1_DIGEST.digest(data.getBytes());
        CommonDigest.SHA224_DIGEST.digest(data.getBytes());
        CommonDigest.SHA256_DIGEST.digest(data.getBytes());
        CommonDigest.SHA512_DIGEST.digest(data.getBytes());
    }   
}
```
* more detail in test case
### 联系方式
<p><a href="guoliao502@163.com">guoliao502@163.com</a></a></p>
