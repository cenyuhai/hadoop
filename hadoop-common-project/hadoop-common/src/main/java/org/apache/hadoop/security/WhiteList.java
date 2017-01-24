/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.security;

import java.io.*;
import java.util.*;

import org.apache.commons.io.Charsets;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.authorize.AuthorizationException;
import org.apache.hadoop.util.StringUtils;

import static org.apache.hadoop.fs.CommonConfigurationKeysPublic.HADOOP_SECURITY_USE_WHITELIST;

/**
 * Management the mapping from ip address to hadoop's username.
 */
public class WhiteList {

  private static final Log LOG = LogFactory.getLog(WhiteList.class);

  public static final String HADOOP_SECURITY_FIXEDWHITELIST_FILE =
          "hadoop.security.fixedwhitelist.file";

  public static final String HADOOP_SECURITY_VARIABLEWHITELIST_FILE =
          "hadoop.security.variablewhitelist.file";

  private volatile boolean enableWhiteList = false;

  // any user can access hdfs from fixed white list's ip address.
  private volatile Set<String> fixedWhiteList = new HashSet<>();
  private volatile Map<String, Set<String>> ip2users = new HashMap<>();

  protected static WhiteList instance = null;

  protected WhiteList() {

  }

  /**
   * singleton pattern and double checking
   */
  public static WhiteList getInstance() {
    if (instance == null) {
      synchronized (WhiteList.class) {
        if (instance == null) {
          instance = new WhiteList();
        }
      }
    }

    return instance;
  }

  public boolean isEnabled() {
    return this.enableWhiteList;
  }


  /**
   * Check the remote ip and username.
   * @param ip remote ip address
   * @param username hadoop's user name
   * @throws AuthorizationException check failed
   */
  public void checkWhiteList(String ip, String username) throws AuthorizationException {

    if (!this.enableWhiteList) {
      return;
    }

    if (this.fixedWhiteList.contains(ip)) {
      return;
    }

    if (!this.ip2users.containsKey(ip)) {
      throw new AuthorizationException(ip + " not in white list.");
    } else {
      Set<String> users = this.ip2users.get(ip);
      if (!users.contains(username)) {
        throw new AuthorizationException(username + " from " + ip + " is illegal.");
      }
    }
  }

  public void init() throws IOException {

    Configuration conf = new Configuration();
    // just load configuration and white list.
    reload(conf);
  }

  /**
   * Reload configuration and white list.
   *
   * @param conf not null
   * @throws IOException load failed
   */
  private void reload(Configuration conf) throws IOException {

    this.enableWhiteList = conf.getBoolean(HADOOP_SECURITY_USE_WHITELIST, false);
    LOG.info("WhiteList checking enable: " + this.enableWhiteList);

    if (!this.enableWhiteList) {
      return;
    }

    loadFixedWhiteList(conf);
    loadVariableWhiteList(conf);
  }

  private void loadFixedWhiteList(Configuration conf) throws IOException {

    // load fixed white list
    String fixedFile = conf.get(HADOOP_SECURITY_FIXEDWHITELIST_FILE);
    if (fixedFile == null || fixedFile.isEmpty()) {
      LOG.error(HADOOP_SECURITY_FIXEDWHITELIST_FILE + " not configured.");
      return;
    }

    File file = new File(fixedFile);
    if (!file.exists()) {
      LOG.error(fixedFile + " not exists!");
      return;
    }

    // new set
    Set<String> newFixedWhiteList = new HashSet<>();
    LOG.info("Loading " + fixedFile);
    try (BufferedReader reader = new BufferedReader(
            new InputStreamReader(new FileInputStream(file), Charsets.UTF_8))) {

      String line;
      while ((line = reader.readLine()) != null) {

        if (LOG.isDebugEnabled()) {
          LOG.debug("handle " + line);
        }

        newFixedWhiteList.add(line);
      }
    }

    LOG.info("Loaded " + fixedFile);

    // switch reference
    this.fixedWhiteList = newFixedWhiteList;
  }

  private void loadVariableWhiteList(Configuration conf) throws IOException {

    // load fixed white list
    String variableFile = conf.get(HADOOP_SECURITY_VARIABLEWHITELIST_FILE);
    if (variableFile == null || variableFile.isEmpty()) {
      LOG.error(HADOOP_SECURITY_VARIABLEWHITELIST_FILE + " not configured.");
      return;
    }

    File file = new File(variableFile);
    if (!file.exists()) {
      LOG.error(variableFile + " not exists!");
      return;
    }

    // new set
    Map<String, Set<String>> newIp2Users = new HashMap<>();
    LOG.info("Loading " + variableFile);
    try (BufferedReader reader = new BufferedReader(
            new InputStreamReader(new FileInputStream(file), Charsets.UTF_8))) {

      String line;
      // 127.0.0.1:user1,user2,user3
      while ((line = reader.readLine()) != null) {

        if (LOG.isDebugEnabled()) {
          LOG.debug("handle " + line);
        }

        String parts[] = StringUtils.split(line, ':');
        if (parts.length != 2) {
          LOG.warn("ignore illegal line: " + line);
          continue;
        }

        String users[] = StringUtils.split(parts[1], ',');
        newIp2Users.put(parts[0], new HashSet<String>(Arrays.asList(users)));
      }
    }

    LOG.info("Loaded " + variableFile);

    // switch reference
    this.ip2users = newIp2Users;
  }

}
