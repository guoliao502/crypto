package studio.guoliao.crypto.constant;

/**
 * User: guoliao
 * Date: 2019/7/25
 * Time: 下午2:03
 * Description:
 */
public enum PBEAlgEnum {

    MD5_DES("PBEWithMD5AndDES"), SHA1_DES("PBEWithSHA1AndDES"),
    SHA1_DESEDE("PBEWITHSHA1ANDDESEDE"), SHA1_AES192_CBC("PBEWITHSHAAND192BITAES-CBC-BC"),
    SHA256_AES128_CBC("PBEWITHSHA256AND128BITAES-CBC-BC"), SHA256_AES192_CBC("PBEWITHSHA256AND192BITAES-CBC-BC"),
    SHA1_AES128_CBC("PBEWITHSHAAND128BITAES-CBC-BC"), SHA1_AES256_CBC("PBEWITHSHAAND256BITAES-CBC-BC"),
    SHA256_AES256_CBC("PBEWITHSHA256AND256BITAES-CBC-BC");

    private String value;

    PBEAlgEnum(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
