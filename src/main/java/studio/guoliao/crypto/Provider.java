package studio.guoliao.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * User: guoliao
 * Date: 2019/7/24
 * Time: 下午2:50
 * Description:
 */
public interface Provider {

    java.security.Provider PROVIDER = new BouncyCastleProvider();
}
