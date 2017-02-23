package org.apache.hadoop.security;

import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.io.Charsets;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.ipc.RefreshHandler;
import org.apache.hadoop.ipc.RefreshRegistry;
import org.apache.hadoop.ipc.RefreshResponse;
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
public class PasswordManager implements RefreshHandler {

  private static final Log LOG = LogFactory.getLog(PasswordManager.class);

  static final String PASSWORD_ENABLE_KEY = "hadoop.security.password.enable";
  static final String PASSWORD_FILE_KEY = "hadoop.security.password.filename";

  static final String EMPTY_PASSWORD = "null";

  private static final String REFRESH_PASSWORD_IDENTIFIER = "REFRESH_PASSWORD";

  private MessageDigest md;  // to compute md5 digest

  // Format1 - username with password and enabled
  //    username:password:true
  // Format2 - username with password and disabled
  //    username:password:false
  // Format3 - username without password and enabled
  //    username:null:true
  // Format4 - username without password and disabled
  //    username:null:false

  private Map<String, PasswordItem> user2Passwd = Collections.unmodifiableMap(new HashMap<String, PasswordItem>());


  // enable password check or not
  private volatile boolean enablePassword = false;

  private static PasswordManager instance = null; // Singleton

  static {
    RefreshRegistry.defaultRegistry().register(REFRESH_PASSWORD_IDENTIFIER, instance);
  }

  private PasswordManager() {

    try {
      this.md = MessageDigest.getInstance("MD5");
    } catch (NoSuchAlgorithmException e) {
      LOG.error("Failed to get Instance of MessageDigest: " + StringUtils.stringifyException(e));
      return;
    }

    Configuration conf = new Configuration();
    try {
      reload(conf);
    } catch (IOException e) {
      LOG.error("Failed to load password from configuration: " + StringUtils.stringifyException(e));
    }

  }

  public static PasswordManager getInstance() {
    if (instance == null) {
      instance = new PasswordManager();
    }

    return instance;
  }

  @Override
  public RefreshResponse handleRefresh(String identifier, String[] args) {
    if (identifier.equals(REFRESH_PASSWORD_IDENTIFIER)) {

      Configuration conf = new Configuration();
      try {
        reload(conf);
      } catch (IOException e) {
        LOG.error("Failed to load password from configuration: " + StringUtils.stringifyException(e));
        return new RefreshResponse(-1, "Refresh failed.");
      }

      return RefreshResponse.successResponse();
    }

    return new RefreshResponse(-1, "Invalid identifier: " + identifier);
  }


  class PasswordItem {
    private String digest;
    private boolean enable;

    PasswordItem(String digest, boolean enable) {
      this.digest = digest;
      this.enable = enable;
    }

    public String getDigest() {
      return digest;
    }

    public boolean isEnable() {
      return enable;
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

    PasswordItem item = this.user2Passwd.get(userName);
    if (item == null) {
      throw new AccessControlException(userName + " not exists.");
    }

    if (!item.isEnable()) {
      return;
    }

    String digest = item.getDigest();
    if (digest == null || digest.isEmpty()) {
      throw new AccessControlException(userName + "'s password not set.");
    }

    if (password == null || password.isEmpty()) {
      throw new AccessControlException(userName + "'s password not specified.");
    }

    String digest2Check = MD5Digest(password);
    if (!digest.equals(digest2Check)) {
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
  protected void reload(Configuration conf) throws IOException {

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
    Map<String, PasswordItem> newUser2Passwd = new HashMap<>();

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
        String password = null;
        if (parts[1] != null && !parts[1].endsWith(EMPTY_PASSWORD)) {
          password = parts[1];
        }

        // parse username and switch
        boolean enable = Boolean.parseBoolean(parts[2]);
        newUser2Passwd.put(parts[0], new PasswordItem(password, enable));
      }
    }
    LOG.info("Loaded " + filename);

    // change reference
    this.user2Passwd = Collections.unmodifiableMap(newUser2Passwd);
  }


}
