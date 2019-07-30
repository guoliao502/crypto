package studio.guoliao;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * Unit test for simple App.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ECBTest.class,
        CBCTest.class, PBETest.class,
        DigestTest.class, KeyUtilTest.class})
public class AppTest {
}
