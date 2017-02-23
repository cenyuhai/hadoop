package org.apache.hadoop.security;

import org.apache.hadoop.conf.Configuration;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.net.URL;

/**
 * Created by lly on 16/12/9.
 */
public class TestPasswordManager {

  @Test
  public void TestPasswordDisabled() throws IOException {

    PasswordManager pm = PasswordManager.getInstance();

    pm.checkPassword("userxxx", "xxxxxx");

    pm.checkPassword("useryyy", null);
  }

  @Test
  public void TestPasswordFileNotSet() throws IOException {

    PasswordManager pm = PasswordManager.getInstance();

    Configuration conf = new Configuration();
    conf.setBoolean(PasswordManager.PASSWORD_ENABLE_KEY, true);

    pm.reload(conf);

    boolean failed = false;
    try {
      pm.checkPassword("user5", "cccccc");
    } catch (AccessControlException e) {
      Assert.assertTrue(e.getMessage().contains("not exists"));
      failed = true;
    }

    Assert.assertTrue(failed);
  }

  @Test
  public void testPasswordManager() throws IOException {
    PasswordManager pm = PasswordManager.getInstance();

    Configuration conf = new Configuration();
    conf.setBoolean(PasswordManager.PASSWORD_ENABLE_KEY, true);

    URL url = TestPasswordManager.class.getClassLoader().getResource("test-password.txt");
    conf.set(PasswordManager.PASSWORD_FILE_KEY, url.getFile());
    pm.reload(conf);

    boolean failed = false;
    try {
      pm.checkPassword("usernotexists", "cccccc"); // not exists
    } catch (AccessControlException e) {
      Assert.assertTrue(e.getMessage().contains("not exists"));
      failed = true;
    }
    Assert.assertTrue(failed);


    failed = false;
    try {
      pm.checkPassword("user1", "aaaaaa"); // comment
    } catch (AccessControlException e) {
      Assert.assertTrue(e.getMessage().contains("not exists"));
      failed = true;
    }
    Assert.assertTrue(failed);

    failed = false;
    try {
      pm.checkPassword("user2", null); // illegal
    } catch (AccessControlException e) {
      Assert.assertTrue(e.getMessage().contains("not exists"));
      failed = true;
    }
    Assert.assertTrue(failed);

    failed = false;
    try {
      pm.checkPassword("user3", "bbbbbb"); // illegal
    } catch (AccessControlException e) {
      Assert.assertTrue(e.getMessage().contains("not exists"));
      failed = true;
    }
    Assert.assertTrue(failed);


    failed = false;
    try {
      pm.checkPassword("user4", null); // password not set
    } catch (AccessControlException e) {
      Assert.assertTrue(e.getMessage().contains("password not set"));
      failed = true;
    }
    Assert.assertTrue(failed);


    pm.checkPassword("user5", "cccccc"); // normal user with passoword

    failed = false;
    try {
      pm.checkPassword("user5", "dddddd"); // password is wrong
    } catch (AccessControlException e) {
      Assert.assertTrue(e.getMessage().contains("password is wrong"));
      failed = true;
    }
    Assert.assertTrue(failed);

    failed = false;
    try {
      pm.checkPassword("user5", null); // password is wrong
    } catch (AccessControlException e) {
      Assert.assertTrue(e.getMessage().contains("password not specified"));
      failed = true;
    }
    Assert.assertTrue(failed);

    pm.checkPassword("user6", null); //password disable
    pm.checkPassword("user6", "eeeeee"); //password disable

    failed = false;
    try {
      pm.checkPassword("user7", null); // password not set
    } catch (AccessControlException e) {
      Assert.assertTrue(e.getMessage().contains("password not set"));
      failed = true;
    }
    Assert.assertTrue(failed);

    pm.checkPassword("user8", null); // password disabled

    ///      disable password check now
    conf.setBoolean(PasswordManager.PASSWORD_ENABLE_KEY, false);
    pm.reload(conf);

    // test again, everything is ok
    pm.checkPassword("usernotexists", "cccccc");
    pm.checkPassword("user1", "aaaaaa"); // comment
    pm.checkPassword("user2", null); // illegal
    pm.checkPassword("user3", "bbbbbb"); // illegal
    pm.checkPassword("user4", null); // password not set
    pm.checkPassword("user5", "cccccc"); // normal user with passoword
    pm.checkPassword("user5", "dddddd"); // password is wrong
    pm.checkPassword("user5", null); // password is wrong

    pm.checkPassword("user6", null); //password disable
    pm.checkPassword("user6", "eeeeee"); //password disable
    pm.checkPassword("user7", null); // password not set
    pm.checkPassword("user8", null); // password disabled

  }

}
