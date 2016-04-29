/*
 * *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements. See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership. The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License. You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * /
 */

package org.apache.hadoop.yarn.server.nodemanager.containermanager.linux.resources;

import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.yarn.conf.YarnConfiguration;
import org.apache.hadoop.yarn.server.nodemanager.containermanager.linux.privileged.PrivilegedOperationExecutor;
import org.apache.hadoop.yarn.server.nodemanager.util.CgroupsLCEResourcesHandler;
import org.apache.hadoop.yarn.server.nodemanager.util.DefaultLCEResourcesHandler;

import java.util.ArrayList;
import java.util.List;

/**
 * Provides mechanisms to get various resource handlers - cpu, memory, network,
 * disk etc., - based on configuration.
 */

@InterfaceAudience.Private
@InterfaceStability.Unstable
public class ResourceHandlerModule {
  static final Log LOG = LogFactory.getLog(ResourceHandlerModule.class);
  private static volatile ResourceHandlerChain resourceHandlerChain;

  /**
   * This specific implementation might provide resource management as well
   * as resource metrics functionality. We need to ensure that the same
   * instance is used for both.
   */
  private static volatile CGroupsHandler cGroupsHandler;
  private static volatile CGroupsMemoryResourceHandlerImpl
      cGroupsMemoryResourceHandler;
  private static volatile CGroupsCpuResourceHandlerImpl
      cGroupsCpuResourceHandler;

  /**
   * Returns an initialized, thread-safe CGroupsHandler instance.
   */
  private static CGroupsHandler getInitializedCGroupsHandler(Configuration conf)
      throws ResourceHandlerException {
    if (cGroupsHandler == null) {
      synchronized (CGroupsHandler.class) {
        if (cGroupsHandler == null) {
          cGroupsHandler = new CGroupsHandlerImpl(conf,
              PrivilegedOperationExecutor.getInstance(conf));
        }
      }
    }

    return cGroupsHandler;
  }

  /**
   * Returns a (possibly null) reference to a cGroupsHandler. This handler is
   * non-null only if one or more of the known cgroups-based resource
   * handlers are in use and have been initialized.
   */

  public static CGroupsHandler getCGroupsHandler() {
    return cGroupsHandler;
  }

  private static CGroupsCpuResourceHandlerImpl getCGroupsCpuResourceHandler(
      Configuration conf) throws ResourceHandlerException {
    boolean cgroupsCpuEnabled =
        conf.getBoolean(YarnConfiguration.NM_CPU_RESOURCE_ENABLED,
            YarnConfiguration.DEFAULT_NM_CPU_RESOURCE_ENABLED);
    boolean cgroupsLCEResourcesHandlerEnabled =
        conf.getClass(YarnConfiguration.NM_LINUX_CONTAINER_RESOURCES_HANDLER,
            DefaultLCEResourcesHandler.class)
            .equals(CgroupsLCEResourcesHandler.class);
    if (cgroupsCpuEnabled || cgroupsLCEResourcesHandlerEnabled) {
      if (cGroupsCpuResourceHandler == null) {
        synchronized (CpuResourceHandler.class) {
          if (cGroupsCpuResourceHandler == null) {
            LOG.debug("Creating new cgroups cpu handler");
            cGroupsCpuResourceHandler =
                new CGroupsCpuResourceHandlerImpl(
                    getInitializedCGroupsHandler(conf));
            return cGroupsCpuResourceHandler;
          }
        }
      }
    }
    return null;
  }

  public static MemoryResourceHandler getMemoryResourceHandler(
      Configuration conf) throws ResourceHandlerException {
    if (conf.getBoolean(YarnConfiguration.NM_MEMORY_RESOURCE_ENABLED,
        YarnConfiguration.DEFAULT_NM_MEMORY_RESOURCE_ENABLED)) {
      return getCgroupsMemoryResourceHandler(conf);
    }
    return null;
  }

  private static CGroupsMemoryResourceHandlerImpl
    getCgroupsMemoryResourceHandler(
      Configuration conf) throws ResourceHandlerException {
    if (cGroupsMemoryResourceHandler == null) {
      synchronized (MemoryResourceHandler.class) {
        if (cGroupsMemoryResourceHandler == null) {
          cGroupsMemoryResourceHandler =
              new CGroupsMemoryResourceHandlerImpl(
                  getInitializedCGroupsHandler(conf));
        }
      }
    }
    return cGroupsMemoryResourceHandler;
  }

  private static void addHandlerIfNotNull(List<ResourceHandler> handlerList,
      ResourceHandler handler) {
    if (handler != null) {
      handlerList.add(handler);
    }
  }

  private static void initializeConfiguredResourceHandlerChain(
      Configuration conf) throws ResourceHandlerException {
    ArrayList<ResourceHandler> handlerList = new ArrayList<>();

    addHandlerIfNotNull(handlerList, getMemoryResourceHandler(conf));
    addHandlerIfNotNull(handlerList, getCGroupsCpuResourceHandler(conf));
    resourceHandlerChain = new ResourceHandlerChain(handlerList);
  }

  public static ResourceHandlerChain getConfiguredResourceHandlerChain(
      Configuration conf) throws ResourceHandlerException {
    if (resourceHandlerChain == null) {
      synchronized (ResourceHandlerModule.class) {
        if (resourceHandlerChain == null) {
          initializeConfiguredResourceHandlerChain(conf);
        }
      }
    }

    if (resourceHandlerChain.getResourceHandlerList().size() != 0) {
      return resourceHandlerChain;
    } else {
      return null;
    }
  }

  @VisibleForTesting
  static void nullifyResourceHandlerChain() throws ResourceHandlerException {
    resourceHandlerChain = null;
  }
}
