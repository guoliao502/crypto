package studio.guoliao.crypto.constant;

/**
 * User: guoliao
 * Date: 2019/7/25
 * Time: 上午11:21
 * Description: 常用padding常量
 *  使用nopadding时，数据需要为对应算法的分块大小
 *      des为8字节的整数倍；aes为16字节
 */
public enum PaddingEnum {

    NO_PADDING("NoPadding"), P1_PADDING("PKCS1Padding"),
    P5_PADDING("PKCS5Padding"), P7_PADDING("PKCS7Padding"),
    OAEP_SHA1_MGF1_PADDING("OAEPWithSHA-1AndMGF1Padding"),
    OAEP_SHA256_MGF1_PADDING("OAEPWithSHA-256AndMGF1Padding");

    private String value;

    PaddingEnum(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
