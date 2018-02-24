extern "C" {
#include "sai.h"
#include "saistatus.h"
#include "saihostif.h"
#include "saisamplepacket.h"
#include "mlnx_flex_bitmap.h"
}
#include <arpa/inet.h>
#include "saihelper.h"
#include <fstream>
#include <iostream>
#include <csignal>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <vector>
#include <set>
#include <mutex>
#include <thread>
#include "bmt_cache_inserter.h"
#include "bmt_cache_evacuator.h"

using namespace std;
extern sai_object_id_t gSwitchId;
extern sai_sai_switch_api_t *sai_switch_api;
extern sai_port_api_t *sai_port_api;
extern sai_tunnel_api_t *sai_tunnel_api;
extern sai_vlan_api_t *sai_vlan_api;
extern sai_bridge_api_t *sai_bridge_api;
extern sai_bmtor_api_t *sai_bmtor_api;



int bmt_cache_evacuator(){
	while (scan_dpdk_port){
		if ((vhost_table.used_entries > (VHOST_TABLE_SIZE-2)) && vhost_table.free_offsets.size<CACHE_EVAC_SIZE){
			// TODO loop over all entries, read counters and catch the mice flows
			// TODO remove mice entry
			lock_guard<mutex> guard(vhost_table.free_offset_mutex);
			uint32_t offset = 0;
			cout << "INFO: cache evacuator freeing vhost table offset " << offset << endl;
			sai_bmtor_api->remove_table_vhost_entry(vhost_table.entry[offset].entry_id);
			vhost_table.free_offsets.push_back(offset);
		}
		
	}
}