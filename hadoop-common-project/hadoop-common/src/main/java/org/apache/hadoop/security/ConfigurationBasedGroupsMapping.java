package org.apache.hadoop.security;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.HashMultimap;
import org.apache.commons.io.Charsets;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.util.StringUtils;

import java.io.*;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@InterfaceAudience.LimitedPrivate({"HDFS", "MapReduce"})
@InterfaceStability.Evolving
public class ConfigurationBasedGroupsMapping
        implements GroupMappingServiceProvider {

  private static final Log LOG = LogFactory.getLog(ConfigurationBasedGroupsMapping.class);


  protected static final String HADOOP_SECURITY_CONFIGURATIONBASED_GROUP_MAPPING_FILE =
            GROUP_MAPPING_CONFIG_PREFIX + ".configurationbased.file";

  private HashMultimap<String, String> user2groups = HashMultimap.create();

  public ConfigurationBasedGroupsMapping() {
    this(new Configuration());
  }

  public ConfigurationBasedGroupsMapping(Configuration conf) {
    try {
      this.reload(conf);
    } catch (IOException e) {
      throw new IllegalStateException(StringUtils.stringifyException(e));
    }
  }

  @VisibleForTesting
  protected HashMultimap<String, String> getUser2groups() {
    return this.user2groups;
  }

  @Override
  public Set<String> getGroups(String user) throws IOException {
    return this.user2groups.get(user);
  }

  @Override
  public void cacheGroupsRefresh() throws IOException {

    Configuration conf = new Configuration();
    this.reload(conf);

  }

  /**
   * Adds groups to cache, no need to do that for this provider
   *
   * @param groups unused
   */
  @Override
  public void cacheGroupsAdd(List<String> groups) throws IOException {
    // does nothing in this provider of user to groups mapping
  }

  /**
   * load configuration file of group mapping.
   * @param conf
   * @throws IOException
   */
  protected void reload(Configuration conf) throws IOException {
    // load fixed white list
    String filename = conf.get(HADOOP_SECURITY_CONFIGURATIONBASED_GROUP_MAPPING_FILE);
    if (filename == null || filename.isEmpty()) {
      LOG.error(HADOOP_SECURITY_CONFIGURATIONBASED_GROUP_MAPPING_FILE + " not configured.");
      return;
    }

    File file = new File(filename);
    if (!file.exists()) {
      LOG.error(filename + " not exists!");
      return;
    }

    // new set
    HashMultimap<String, String> newUser2groups = HashMultimap.create();
    LOG.info("Loading " + filename);
    try (BufferedReader reader = new BufferedReader(
            new InputStreamReader(new FileInputStream(file), Charsets.UTF_8))) {

      String line;
      // user=group1,group2,group3
      while ((line = reader.readLine()) != null) {

        if (LOG.isDebugEnabled()) {
          LOG.debug("handle " + line);
        }

        Collection<String> userToGroups = StringUtils.getStringCollection(line,
                "=");
        if (userToGroups.size() != 2) {
          LOG.warn("ignore invalid mapping: " + line);
          continue;
        }

        String[] userToGroupsArray = userToGroups.toArray(new String[userToGroups
                .size()]);
        String user = userToGroupsArray[0];
        Set<String> groups = new HashSet<>(StringUtils.getStringCollection(userToGroupsArray[1]));

        newUser2groups.putAll(user, groups);
      }
    }

    LOG.info("Loaded " + newUser2groups.keySet().size() + " users from " + filename);

    // switch reference
    this.user2groups = newUser2groups;
  }
}
