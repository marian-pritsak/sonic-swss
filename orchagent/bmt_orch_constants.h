
#ifndef __BMT_ORCH_CONSTANTS_H_
#define __BMT_ORCH_CONSTANTS_H_


/* Constants */
#define DPDK_FRONT_PORT 7
#define PACKETS_PER_SAMPLE 1 // ratio of dpdk packets to samples generated
#define VHOST_TABLE_SIZE 10 // TODO
#define UNREFERENCED_PARAMETER(P)       (P)
#define DEFAULT_IF	"Ethernet24" // sampler socket
#define BUF_SIZE		1024 // sampler buffer size
#define CONTROL_MTU 1100 //TODO
#define ETHER_TYPE	0x0800
#define TYPE_VLAN 0x8100
#define TYPE_IPV4 0x0800
#define CACHE_EVAC_SIZE (1) // the number of expected elements in vhost_table.free_offsets
#define EVAC_BATCH_SIZE (3) // number of counters to probe each time
#define EVAC_TRESH (1*EVAC_BATCH_SIZE) // maximal counter value for evacuation
#define INSERTER_WINDOW_SIZE 20
#define INSERTER_TRESH 4 // minimal number of packet from flow in a sampling window for cache insertion
#endif /** __BMT_ORCH_CONSTANTS_H_ */
