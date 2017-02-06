package org.apache.hadoop.security;

/**
 * Created by user on 26/01/2017.
 */

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.authorize.AuthorizationException;
import org.junit.*;

import static org.apache.hadoop.fs.CommonConfigurationKeysPublic.HADOOP_SECURITY_USE_WHITELIST;

public class TestIP2UsersWhiteList {

  private final String ip1 = "192.168.1.1";
  private final String ip2 = "192.168.1.2";
  private final String ip3 = "192.168.1.3";
  private final String ip4 = "192.168.1.34";
  private final String ip5 = "192.168.1.100";
  private final String ip6 = "192.168.1.200";

  private final String user1 = "user1";
  private final String user2 = "user2";
  private final String user3 = "user3";
  private final String user4 = "user4";

  private final String fixedFileName = "test-fixedwhitelist";
  private final String variableFileName = "test-variablewhitelist";


  @Test
  public void testWhiteListDefault() {

    IP2UsersWhiteList whiteList = IP2UsersWhiteList.getInstance();

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

    String fixedPath = TestIP2UsersWhiteList.class.getClassLoader().getResource(fixedFileName).getPath();
    String variabledPath = TestIP2UsersWhiteList.class.getClassLoader().getResource(variableFileName).getPath();

    conf.set(IP2UsersWhiteList.HADOOP_SECURITY_FIXEDWHITELIST_FILE, fixedPath);
    conf.set(IP2UsersWhiteList.HADOOP_SECURITY_VARIABLEWHITELIST_FILE, variabledPath);

    IP2UsersWhiteList whiteList = IP2UsersWhiteList.getInstance();
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

    // case6 comment fixed white list - bad case four
    pass = true;
    try {
      whiteList.checkWhiteList(ip5, user1);
    } catch (AuthorizationException e) {
      pass = false;
    }
    Assert.assertFalse(pass);

    // case7 comment variable white list - bad case five
    pass = true;
    try {
      whiteList.checkWhiteList(ip6, user4);
    } catch (AuthorizationException e) {
      pass = false;
    }
    Assert.assertFalse(pass);
  }


}
