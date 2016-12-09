package org.apache.hadoop.security;

import org.apache.commons.io.Charsets;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.util.StringUtils;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by lly on 16/12/9.
 */
public class PasswordManager {

  private static final Log LOG = LogFactory.getLog(PasswordManager.class);

  static final String PASSWORD_ENABLE_KEY = "hadoop.security.password.enable";
  static final String PASSWORD_FILE_KEY = "hadoop.security.password.filename";

  static final String EMPTY_PASSWORD = "null";

  private MessageDigest md;  // to compute md5 digest

  // Format1 - username with password and enabled
  //    username:password:true
  // Format2 - username with password and disabled
  //    username:password:false
  // Format3 - username without password and enabled
  //    username:null:true
  // Format4 - username without password and disabled
  //    username:null:false

  private volatile Map<String, String> user2Passwd = Collections.unmodifiableMap(new HashMap<String, String>());
  private volatile Map<String, Boolean> user2Switch = Collections.unmodifiableMap(new HashMap<String, Boolean>());


  // enable password check or not
  private volatile boolean enablePassword = false;

  public void init() throws IOException {

    Configuration conf = new Configuration();
    // just load configuration and password map.
    reload(conf);

    try {
      this.md = MessageDigest.getInstance("MD5");
    } catch (NoSuchAlgorithmException e) {
      throw new IOException("Failed to get Instance of MessageDigest: " + StringUtils.stringifyException(e));
    }

  }

  /**
   * Check as follows:
   *  I. user exists or not;
   *  II. password set or not;
   *  III. password right or wrong.
   * @param userName user's account name
   * @param password password in plain text
   */
  public void checkPassword(String userName, String password) throws AccessControlException {

    if (!this.enablePassword) {
      return;
    }

    Boolean _switch = this.user2Switch.get(userName);
    if (_switch == null) {
      throw new AccessControlException(userName + " not exists.");
    }

    if (!_switch.booleanValue()) {
      return;
    }

    String passwdDigest = this.user2Passwd.get(userName);
    if (passwdDigest == null || passwdDigest.isEmpty()) {
      throw new AccessControlException(userName + "'s password not set.");
    }

    if (password == null || password.isEmpty()) {
      throw new AccessControlException(userName + "'s password not specified.");
    }

    String digest2Check = MD5Digest(password);
    if (!passwdDigest.equals(digest2Check)) {
      throw new AccessControlException(userName + "'s password is wrong.");
    }

  }

  private String MD5Digest(String original) {

    this.md.reset();

    md.update(original.getBytes());
    byte[] digest = md.digest();

    StringBuilder sb = new StringBuilder();
    for (byte b : digest) {
      sb.append(String.format("%02x", b & 0xff));
    }

    return sb.toString();
  }


  /**
   * Reload configuration and password map.
   * @param conf not null
   * @throws IOException  load failed
   */
  public void reload(Configuration conf) throws IOException {

    this.enablePassword = conf.getBoolean(PASSWORD_ENABLE_KEY, false);
    LOG.info("Password checking enable: " + this.enablePassword);

    if (!this.enablePassword) {
      return;
    }

    String filename = conf.get(PASSWORD_FILE_KEY);

    if (filename == null || filename.isEmpty()) {
      LOG.error(PASSWORD_FILE_KEY + " not configured.");
      return;
    }

    File file = new File(filename);
    if (!file.exists()) {
      LOG.error(filename + " not exists!");
      return;
    }

    // new map
    Map<String, String> newUser2Passwd = new HashMap<>();
    Map<String, Boolean> newUser2Switch = new HashMap<>();

    LOG.info("Loading " + filename);
    try (BufferedReader reader = new BufferedReader(
            new InputStreamReader(new FileInputStream(file),Charsets.UTF_8))){

      String line;
      while ((line = reader.readLine()) != null) {

        if (line.startsWith("#")) {
          continue; // skip comment
        }

        String[] parts = line.split(":");
        if (parts.length != 3) {
          LOG.warn("Illegal password item: " + line);
          continue;
        }

        // parse username and password
        if (parts[1] != null && !parts[1].endsWith(EMPTY_PASSWORD)) {
          newUser2Passwd.put(parts[0], parts[1]);
        }

        // parse username and switch
        boolean _switch = Boolean.parseBoolean(parts[2]);
        newUser2Switch.put(parts[0], _switch);
      }
    }
    LOG.info("Loaded " + filename);

    // change reference
    this.user2Passwd = Collections.unmodifiableMap(newUser2Passwd);
    this.user2Switch = Collections.unmodifiableMap(newUser2Switch);
  }


}
