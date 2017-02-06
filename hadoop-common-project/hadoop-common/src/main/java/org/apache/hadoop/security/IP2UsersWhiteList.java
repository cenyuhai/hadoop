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


import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import org.apache.commons.io.Charsets;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.ipc.RefreshHandler;
import org.apache.hadoop.ipc.RefreshRegistry;
import org.apache.hadoop.ipc.RefreshResponse;
import org.apache.hadoop.security.authorize.AuthorizationException;
import org.apache.hadoop.util.StringUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import static org.apache.hadoop.fs.CommonConfigurationKeysPublic.HADOOP_SECURITY_USE_WHITELIST;

/**
 * Management the mapping from ip address to hadoop's username.
 */
public class IP2UsersWhiteList implements RefreshHandler {

  private static final Log LOG = LogFactory.getLog(WhiteList.class);

  public static final String HADOOP_SECURITY_FIXEDWHITELIST_FILE =
          "hadoop.security.fixedwhitelist.file";

  public static final String HADOOP_SECURITY_VARIABLEWHITELIST_FILE =
          "hadoop.security.variablewhitelist.file";

  private static final String REFRESH_WHITE_LIST_IDENTIFIER = "REFRESH_WHITE_LIST";

  private volatile boolean enableWhiteList = false;

  // any user can access hdfs from fixed white list's ip address.
  private Set<String> fixedWhiteList = new HashSet<>();
  private  Multimap<String, String> ip2users = HashMultimap.create();

  protected static final IP2UsersWhiteList instance = new IP2UsersWhiteList();

  static {
    RefreshRegistry.defaultRegistry().register(REFRESH_WHITE_LIST_IDENTIFIER, instance);
  }

  private IP2UsersWhiteList() {

    Configuration conf = new Configuration();
    // just load configuration and white list.
    reload(conf);
  }

  /**
   * singleton pattern and double checking
   */
  public static IP2UsersWhiteList getInstance() {
    return instance;
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

    if (!this.ip2users.containsEntry(ip, username)) {
      throw new AuthorizationException(username + " from " + ip + " not in white list.");
    }
  }

  @Override
  public RefreshResponse handleRefresh(String identifier, String[] args) {

    if (identifier.equals(REFRESH_WHITE_LIST_IDENTIFIER)) {

      Configuration conf = new Configuration();
      reload(conf);

      return RefreshResponse.successResponse();
    }

    return new RefreshResponse(-1, "Invalid identifier: " + identifier);
  }

  /**
   * Reload configuration and white list.
   *
   * @param conf not null
   * @throws IOException load failed
   */
  @VisibleForTesting
  public void reload(Configuration conf) {

    this.enableWhiteList = conf.getBoolean(HADOOP_SECURITY_USE_WHITELIST, false);
    LOG.info("WhiteList checking enable: " + this.enableWhiteList);

    if (!this.enableWhiteList) {
      return;
    }

    try {
      loadFixedWhiteList(conf);
      loadVariableWhiteList(conf);
    } catch (IOException e) {
      LOG.error("Error reloading white list. ", e);
    }

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
    LOG.info("Loading new fixed WhiteList file: " + fixedFile);
    try (BufferedReader reader = new BufferedReader(
            new InputStreamReader(new FileInputStream(file), Charsets.UTF_8))) {

      String line;
      while ((line = reader.readLine()) != null) {

        if (LOG.isDebugEnabled()) {
          LOG.debug("Loading new fixed WhiteList file: Handle " + line);
        }

        // skip empty line and comment
        line = line.trim();
        if (line.isEmpty() || line.startsWith("#")) {
          continue;
        }

        newFixedWhiteList.add(line);
      }
    }

    LOG.info("Loaded " + newFixedWhiteList.size() + " from " + fixedFile);

    if (newFixedWhiteList.size() == 0) {
      LOG.error("Fixed white list can't be empty. Ignore.");
    } else {
      // switch reference
      this.fixedWhiteList = newFixedWhiteList;
    }
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
    Multimap<String, String> newIp2Users = HashMultimap.create();
    LOG.info("Loading new variable WhiteList file: " + variableFile);
    try (BufferedReader reader = new BufferedReader(
            new InputStreamReader(new FileInputStream(file), Charsets.UTF_8))) {

      String line;
      // 127.0.0.1=user1,user2,user3
      while ((line = reader.readLine()) != null) {

        if (LOG.isDebugEnabled()) {
          LOG.debug("Loading new variable WhiteList file: Handle " + line);
        }

        // skip empty line and comment
        line = line.trim();
        if (line.isEmpty() || line.startsWith("#")) {
          continue;
        }

        Collection<String> ipToUsers = StringUtils.getStringCollection(line,
                "=");
        if (ipToUsers.size() != 2) {
          LOG.warn("ignore invalid line: " + line);
          continue;
        }

        String[] ipToUsersArray = ipToUsers.toArray(new String[ipToUsers
                .size()]);
        String ip = ipToUsersArray[0];
        Set<String> users = new HashSet<>(StringUtils.getStringCollection(ipToUsersArray[1]));

        newIp2Users.putAll(ip, users);
      }
    }

    LOG.info("Loaded " + newIp2Users.keys().size() + " from " + variableFile);

    // switch reference
    this.ip2users = newIp2Users;
  }


}