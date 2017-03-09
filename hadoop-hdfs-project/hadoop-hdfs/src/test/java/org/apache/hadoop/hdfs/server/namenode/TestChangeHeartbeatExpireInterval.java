package org.apache.hadoop.hdfs.server.namenode;

/**
 * Created by user on 12/01/2017.
 */

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.DFSConfigKeys;
import org.apache.hadoop.hdfs.HdfsConfiguration;
import org.apache.hadoop.hdfs.MiniDFSCluster;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

public class TestChangeHeartbeatExpireInterval {

  @Test
  public void testChangeHeartbeatExpireInterval() throws IOException {

    Configuration conf = new HdfsConfiguration();


    MiniDFSCluster cluster = null;
    try {
      cluster = new MiniDFSCluster
              .Builder(conf)
              .numDataNodes(1)
              .storagesPerDatanode(1)
              .build();
      cluster.waitActive();

      final long heartbeatIntervalSeconds = conf.getLong(
              DFSConfigKeys.DFS_HEARTBEAT_INTERVAL_KEY,
              DFSConfigKeys.DFS_HEARTBEAT_INTERVAL_DEFAULT);
      final int heartbeatRecheckInterval = conf.getInt(
              DFSConfigKeys.DFS_NAMENODE_HEARTBEAT_RECHECK_INTERVAL_KEY,
              DFSConfigKeys.DFS_NAMENODE_HEARTBEAT_RECHECK_INTERVAL_DEFAULT); // 5 minutes
      final long expectExpireMS = 2 * heartbeatRecheckInterval
              + 10 * 1000 * heartbeatIntervalSeconds;

      long expireMS = cluster.getNameNode().namesystem.getBlockManager()
              .getDatanodeManager().getHeartbeatExpireInterval();
      Assert.assertEquals(expectExpireMS, expireMS);

      // change to 1 hour
      cluster.getNameNode().namesystem.getBlockManager()
              .getDatanodeManager().setHeartbeatExpireInterval(3600000);
      expireMS = cluster.getNameNode().namesystem.getBlockManager()
              .getDatanodeManager().getHeartbeatExpireInterval();
      Assert.assertEquals(3600000, expireMS);

       // change to default
      cluster.getNameNode().namesystem.getBlockManager()
              .getDatanodeManager().setHeartbeatExpireInterval(DFSConfigKeys.DFS_HEARTBEAT_EXPIRE_INTERVAL_DEFAULT);
      expireMS = cluster.getNameNode().namesystem.getBlockManager()
              .getDatanodeManager().getHeartbeatExpireInterval();
      Assert.assertEquals(expectExpireMS, expireMS);

      // change block invalidate limit
      cluster.getNameNode().namesystem.getBlockManager()
              .getDatanodeManager().setBlockInvalidateLimit(10000);
      int limit = cluster.getNameNode().namesystem.getBlockManager()
              .getDatanodeManager().getBlockInvalidateLimit();
      Assert.assertEquals(10000, limit);

    } finally {
      if (cluster != null) {
        cluster.shutdown();
      }
    }

  }


}
