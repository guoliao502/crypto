package studio.guoliao.crypto.model;

/**
 * User: guoliao
 * Date: 2019/7/23
 * Time: 下午7:33
 * Description:
 */
public class KeyDescription {

    private static final String AES = "AES";

    private static final String DES = "DES";

    private static final String DESede = "DESede";

    public static final KeyDescription AES_128 = new KeyDescription(AES, 128);

    public static final KeyDescription AES_192 = new KeyDescription(AES, 192);

    public static final KeyDescription AES_256 = new KeyDescription(AES, 256);

    public static final KeyDescription DES_56 = new KeyDescription(DES, 56);

    public static final KeyDescription DESede_168 = new KeyDescription(DESede, 168);

    private String alg;

    private int length;

    public KeyDescription(String alg, int length) {
        this.alg = alg;
        this.length = length;
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }
}
