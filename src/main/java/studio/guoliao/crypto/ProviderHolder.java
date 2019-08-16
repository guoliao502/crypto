package studio.guoliao.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;

/**
 * User: guoliao
 * Date: 2019/7/24
 * Time: 下午2:50
 * Description: crypto实现调用的算法提供者
 */
public interface ProviderHolder {

    java.security.Provider PROVIDER = new BouncyCastleProvider();

    static ProviderHolder newInstance(){
        return new ProviderHolder() {
            private Provider provider = PROVIDER;
            @Override
            public void setProvider(Provider provider) {
                this.provider = provider;
            }
            @Override
            public Provider getProvider(){
                return this.provider;
            }
        };
    }

    void setProvider(Provider provider);

    default Provider getProvider(){
        return PROVIDER;
    }
}
