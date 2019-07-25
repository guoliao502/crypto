package studio.guoliao.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * User: guoliao
 * Date: 2019/7/23
 * Time: 下午6:00
 * Description:
 */
public interface Digest {

    Logger LOGGER = LoggerFactory.getLogger(Digest.class);

    byte[] digest(byte[] data);
}
