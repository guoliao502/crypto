package studio.guoliao.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;

/**
 * User: guoliao
 * Date: 2019/7/24
 * Time: 下午2:50
 * Description:
 */
public interface ProviderHolder {

    java.security.Provider PROVIDER = new BouncyCastleProvider();

    Logger LOGGER = LoggerFactory.getLogger(ProviderHolder.class);

    void setProvider(Provider provider);
}
