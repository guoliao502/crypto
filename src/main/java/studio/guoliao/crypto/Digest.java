package studio.guoliao.crypto;

import java.security.NoSuchAlgorithmException;


/**
 * User: guoliao
 * Date: 2019/7/23
 * Time: 下午6:00
 * Description:
 */
public interface Digest extends ProviderHolder {

    byte[] digest(byte[] data) throws NoSuchAlgorithmException;
}
