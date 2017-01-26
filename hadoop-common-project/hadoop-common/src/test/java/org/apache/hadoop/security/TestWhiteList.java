package org.apache.hadoop.security;

/**
 * Created by user on 26/01/2017.
 */

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.authorize.AuthorizationException;
import org.junit.*;

import static org.apache.hadoop.fs.CommonConfigurationKeysPublic.HADOOP_SECURITY_USE_WHITELIST;

public class TestWhiteList {

  private final String ip1 = "192.168.1.1";
  private final String ip2 = "192.168.1.2";
  private final String ip3 = "192.168.1.3";
  private final String ip4 = "192.168.1.34";

  private final String user1 = "user1";
  private final String user2 = "user2";
  private final String user3 = "user3";

  private final String fixedFileName = "test-fixedwhitelist";
  private final String variableFileName = "test-variablewhitelist";


  @Test
  public void testWhiteListDefault() {

    WhiteList whiteList = WhiteList.getInstance();

    boolean pass = true;
    try {
      whiteList.checkWhiteList(ip1, user1);
      whiteList.checkWhiteList(ip2, user2);
      whiteList.checkWhiteList(ip3, user3);
    } catch (AuthorizationException e) {
      pass = false;
    }

    Assert.assertTrue(pass);
  }

  @Test
  public void testWhiteListEnable() {

    Configuration conf = new Configuration();
    conf.setBoolean(HADOOP_SECURITY_USE_WHITELIST, true);

    String fixedPath = TestWhiteList.class.getClassLoader().getResource(fixedFileName).getPath();
    String variabledPath = TestWhiteList.class.getClassLoader().getResource(variableFileName).getPath();

    conf.set(WhiteList.HADOOP_SECURITY_FIXEDWHITELIST_FILE, fixedPath);
    conf.set(WhiteList.HADOOP_SECURITY_VARIABLEWHITELIST_FILE, variabledPath);

    WhiteList whiteList = WhiteList.getInstance();
    whiteList.reload(conf);

    // case1 fix white list
    boolean pass = true;
    try {
      whiteList.checkWhiteList(ip1, user1);
      whiteList.checkWhiteList(ip1, user2);
      whiteList.checkWhiteList(ip1, user3);
    } catch (AuthorizationException e) {
      pass = false;
    }

    Assert.assertTrue(pass);

    // case2 variable white list - good case
    try {
      whiteList.checkWhiteList(ip2, user1);
      whiteList.checkWhiteList(ip2, user2);
      whiteList.checkWhiteList(ip3, user3);
    } catch (AuthorizationException e) {
      pass = false;
    }
    Assert.assertTrue(pass);


    // case3 variable white list - bad case one
    try {
      whiteList.checkWhiteList(ip2, user3);
    } catch (AuthorizationException e) {
      pass = false;
    }
    Assert.assertFalse(pass);

    // case4 variable white list - bad case two
    pass = true;
    try {
      whiteList.checkWhiteList(ip3, user1);
    } catch (AuthorizationException e) {
      pass = false;
    }
    Assert.assertFalse(pass);

    // case5 variable white list - bad case three
    pass = true;
    try {
      whiteList.checkWhiteList(ip4, user1);
    } catch (AuthorizationException e) {
      pass = false;
    }
    Assert.assertFalse(pass);
  }


}
