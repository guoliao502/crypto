package studio.guoliao.crypto;

import java.security.NoSuchAlgorithmException;


/**
 * User: guoliao
 * Date: 2019/7/23
 * Time: 下午6:00
 * Description: 摘要算法功能
 */
public interface Digest extends ProviderHolder {

    byte[] digest(byte[] data) throws NoSuchAlgorithmException;

    String digestToBase64(byte[] data) throws NoSuchAlgorithmException;

    String digestToHex(byte[] data) throws NoSuchAlgorithmException;
}
