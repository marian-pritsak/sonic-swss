#ifndef __BMT_COMMON_H_
#define __BMT_COMMON_H_

extern "C" {
#include "sai.h"
#include "saistatus.h"
}
 
#include <sairedis.h>

#include <fstream>
#include <iostream>
#include <mutex>

#include "macaddress.h"

#include "bmt_orch_constants.h"


typedef struct bmt_init_status_t{
  bool tunnel_encap_map_created = false;
  bool tunnel_decap_map_created = false;
  bool tunnel_decap_map_entry_created = false;
  bool tunnel_encap_map_entry_created = false;
  bool tunnel_created = false;
  bool tunnel_term_table_entry_created = false;
  bool vhost_table_entry_created = false;
  bool default_vhost_table_entry_created = false;
  bool peering_entry_created = false;
  bool sai_ext_api_inited = false;
  bool vlan_created = false;
  bool vlan_member_created = false;
  bool dpdk_vlan_member_created = false;
  bool bridge_created = false;
  bool bridge_port_created = false;
  bool dpdk_bridge_port_created = false;
} bmt_init_status_t;

#define DEFAULT_BATCH_SIZE  128

/* Global variables, all in one struct TODO- convert to a class + instance*/
typedef struct app_config {
    sai_object_id_t virtualRouterId;
    sai_object_id_t underlayIfId;
    // sai_object_id_t default_vhost_table_entry;
    swss::MacAddress macAddress;
    int batchSize = DEFAULT_BATCH_SIZE;
    bool sairedisRecord = true;
    bool swssRecord = true;
    bool logRotate = false;
    std::ofstream recordOfs;
    std::string recordFile;

    // controls
    bool exitFlag     = false;
    bool scanDpdkPort = true;
    bool flushCache   = false;
    bool pauseCacheInsertion = false;
    int sampler_init_status = -1;
    uint32_t insertionWindowSize = INSERTER_WINDOW_SIZE;
    uint32_t insertionThreshold = INSERTER_THRESH;
    uint32_t evacuationThreshold = EVAC_TRESH;

    // stats
    uint32_t cacheInsertCount = 0;
    uint32_t cacheInsertSkip = 0;
    uint32_t cacheRemoveCount = 0;
    uint64_t entryCounters[VHOST_TABLE_SIZE];

    /* Global database mutex */
    std::mutex dbMutex;
} global_config_t;

sai_object_id_t sai_get_port_id_by_front_port(uint32_t hw_port);
void  bmt_deinit(bmt_init_status_t* bmt_common_init);
int   bmt_init(bmt_init_status_t* bmt_common_init);
void  bmt_cache_start();

#endif /* __BMT_COMMON_H_ */
