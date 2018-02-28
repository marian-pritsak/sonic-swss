
#if !defined (__BMT_ORCH_CONSTANTS_H_)
#define __BMT_ORCH_CONSTANTS_H_


/* Constants */
#define DPDK_FRONT_PORT 7
#define PACKETS_PER_SAMPLE 10 // ratio of dpdk packets to samples generated
#define VHOST_TABLE_SIZE 10 // TODO
#define UNREFERENCED_PARAMETER(P)       (P)
#define CONTROL_MTU 1100 //TODO
#define TYPE_VLAN 0x8100
#define TYPE_IPV4 0x0800
#define CACHE_EVAC_SIZE (1) // the number of expected elements in vhost_table.free_offsets


#endif /** __BMT_ORCH_CONSTANTS_H_ */
