extern "C" {
#include "sai.h"
#include "saistatus.h"
#include "saihostif.h"
#include "saisamplepacket.h"
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
#include <pcap.h>
#include "bmt_orch_constants.h"
#include "bmt_common.h"
#include "bmt_cache_inserter.h"
#include "bmtorcacheorch.h"
#include "logger.h"
#include <unistd.h>
#include <string.h>
#include "portsorch.h"
#include "ipprefix.h"


#include <linux/if_packet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <ctime>
#include <cstdlib>


using namespace std;
extern sai_hostif_api_t *sai_hostif_api;
extern sai_samplepacket_api_t *sai_samplepacket_api;
extern sai_port_api_t *sai_port_api;
extern sai_switch_api_t *sai_switch_api;
extern sai_bmtor_api_t *sai_bmtor_api;

//mutex cout_mutex;
extern PortsOrch *gPortsOrch;
extern BmToRCacheOrch *gBmToRCacheOrch;

typedef struct bmt_dpdk_pkt_t {
    bool valid;
    uint32_t underlay_dip;
    uint32_t overlay_dip;
    uint32_t vni;
} bmt_dpdk_pkt_t;

typedef struct bmt_vhost_entry_t { //TODDO - change to map<offset:entry_id>?
    sai_object_id_t entry_id;
    uint32_t overlay_dip;
    uint32_t underlay_dip;
    uint32_t vni;
}bmt_vhost_entry_t;


typedef struct bmt_vhost_table_t {
    bmt_vhost_entry_t   entry[VHOST_TABLE_SIZE];
    uint32_t            used_entries=0;
    mutex               free_offset_mutex;
    vector<uint32_t>    free_offsets; // TODO implement cache evac
} bmt_vhost_table_t;


/* Global variables */
extern sai_object_id_t gSwitchId;
extern sai_object_id_t dpdk_port;
sai_object_id_t samplepacketOid;
sai_object_id_t samplepackettrapOid;
sai_object_id_t trapGroupOid;
sai_object_id_t hostifOid;
sai_object_id_t hostif_table_entryOid;
sai_object_id_t trapgroupOid;
bmt_vhost_table_t vhost_table;
extern bool gScanDpdkPort;
extern bool gFlushCache;
extern bool gExitFlag;

sai_status_t bmt_get_free_offset(uint32_t* offset_ptr){
    if (vhost_table.used_entries > (VHOST_TABLE_SIZE-2)){
        //TODO take from free list when cache evac is working.
        if (vhost_table.free_offsets.size()>0){
            *offset_ptr = vhost_table.free_offsets.back();
            vhost_table.free_offsets.pop_back();
            SWSS_LOG_ERROR("[inserter] INFO: cache full, replacing chace entry: %u", *offset_ptr);
            return SAI_STATUS_SUCCESS;
        }
        else{
            SWSS_LOG_ERROR("[inserter] WARNING: no avaliable entries is cache, please check eviction.");
            return SAI_STATUS_FAILURE;
        }
    }
    else{
        SWSS_LOG_ERROR("[inserter] INFO: cache has unused entries, using entry %u/%u", vhost_table.used_entries, VHOST_TABLE_SIZE-1);
        *offset_ptr = vhost_table.used_entries;
        vhost_table.used_entries++;
        return SAI_STATUS_SUCCESS;
    }

}

sai_status_t bmt_cache_insert_vhost_entry(uint32_t overlay_dip, uint32_t underlay_dip, uint32_t vni){
    lock_guard<mutex> guard(vhost_table.free_offset_mutex);
    uint32_t offset;
    sai_status_t status = bmt_get_free_offset(&offset);

    SWSS_LOG_NOTICE("Vhost Enry creation. underlay dip 0x%x overlay_dip 0x%x. vni %d", underlay_dip, overlay_dip, vni);
    sai_object_id_t entry_id;
    status = gBmToRCacheOrch->CreateVhostEntry(&entry_id, IpAddress(htonl(underlay_dip)), IpAddress(htonl(overlay_dip)), vni);
    if (status != SAI_STATUS_SUCCESS){
        SWSS_LOG_ERROR("[inserter] ERROR: failed to insert vhost rule, rv: %u", status);
        return status;
    }

    vhost_table.entry[offset].overlay_dip = overlay_dip;
    vhost_table.entry[offset].underlay_dip = underlay_dip;
    vhost_table.entry[offset].vni = vni;
    vhost_table.entry[offset].entry_id = entry_id;
    return SAI_STATUS_SUCCESS;
}

// sai_status_t bmt_parse_packet(uint8_t* buf, sai_size_t buffer_size, bmt_dpdk_pkt_t *pkt){
void bmt_parse_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buf) {
//--------------------------------------
// netdev encap via ip4 packet: so vxlan is shifted:
// L2 (0-13) => L3 (14-33) => udp (34-41) => vxlan (42-49) => L2 (50-63) => L3 (64-83)  
    sai_size_t buffer_size = header->len;
    SWSS_LOG_ERROR("[inserter] [recv] parsing packet of len %d", header->len);
    // pkt->valid = false;
    uint16_t etherType[2];
    uint8_t vxlan_flags;
    uint8_t inner_ipv4_ver;
    uint8_t outer_ipv4_ver;
    uint32_t vni;
    uint32_t underlay_dip;
    uint32_t overlay_dip;
    if (buffer_size >= 84){ // TODO should be 84
        etherType[0]   = (uint16_t)(((uint16_t)buf[12]<<8)|(uint16_t)buf[13]); // outer L2 etherType (tagged)
        outer_ipv4_ver = (uint8_t)(buf[14]>>4);
        vxlan_flags    = (uint8_t) buf[42]; // inner L2 etherType
        etherType[1]   = (uint16_t)(((int)buf[62]<<8)|(int)buf[63]); // inner etherType
        inner_ipv4_ver = (uint8_t)(buf[64]>>4);      
        if(
            etherType[0]    == TYPE_IPV4 &&
            etherType[1]    == TYPE_IPV4 &&
            vxlan_flags     == 8         &&
            outer_ipv4_ver  == 4         &&
            inner_ipv4_ver  == 4
        )
        {
            // pkt->valid = true;
            vni = (((uint32_t)buf[46])<<16) | (((uint32_t)buf[47])<<8) | ((uint32_t)buf[48]);
            underlay_dip = ((uint32_t)buf[30]<<24) | ((uint32_t)buf[31]<<16) | ((uint32_t)buf[32]<<8) | ((uint32_t)buf[33]); 
            overlay_dip = ((uint32_t)buf[80]<<24) | ((uint32_t)buf[81]<<16) | ((uint32_t)buf[82]<<8) | ((uint32_t)buf[83]); 
            SWSS_LOG_NOTICE("[inserter] [recv] packet parsed successfully:");
            SWSS_LOG_NOTICE("[inserter] [recv]    underlay ip=%d.%d.%d.%d",int(buf[30]),int(buf[31]),int(buf[32]),int(buf[33]));
            SWSS_LOG_NOTICE("[inserter] [recv]    overlay  ip=%d.%d.%d.%d",int(buf[80]),int(buf[81]),int(buf[82]),int(buf[83]));
            SWSS_LOG_NOTICE("[inserter] [recv]    vni= %d",int(vni));
            sai_status_t status = bmt_cache_insert_vhost_entry(overlay_dip, underlay_dip, vni);
            SWSS_LOG_NOTICE("[inserter] [recv]    bmt_cache_insert_vhost_entry. status = %d",status);
        }
        else {
            SWSS_LOG_NOTICE("[inserter] [recv] not vxlan packet");
        }
    }
    else {
            SWSS_LOG_NOTICE("[inserter] [recv] short packet");
    }
}

sai_status_t bmt_get_port_vect_from_vni(uint32_t vni, uint16_t* port_vect){
    // TODO implement
    *port_vect = (uint16_t) 0xfff;
    return SAI_STATUS_SUCCESS;
}

/* receive flow */
// int bmt_recv(int sockfd){
//     SWSS_LOG_ENTER();
//     uint8_t buf[BUF_SIZE];
//     ssize_t buffer_size;
//     sai_status_t status;
//     bmt_dpdk_pkt_t pkt;

//     while(gScanDpdkPort)
//     { 
//         SWSS_LOG_NOTICE("[inserter] listening ...");
//         buffer_size = recvfrom(sockfd, buf, BUF_SIZE, 0, NULL, NULL);
//         SWSS_LOG_NOTICE("[inserter] recv packet, size = %lu",buffer_size);
//         status = bmt_parse_packet(buf, buffer_size,&pkt);
//         if (status != SAI_STATUS_SUCCESS){
//             SWSS_LOG_ERROR("[inserter] BMtor_dpdk_sampler :  bmt_parse_packet , status %d", status);
//             continue;
//         }
//         if (!pkt.valid) continue;
//         sleep(1); // TODO remove!!!
//         // status = bmt_cache_insert_vhost_entry(pkt.overlay_dip, pkt.underlay_dip, pkt.vni);
//         if (status != SAI_STATUS_SUCCESS) 
//             continue;
//     }
//     SWSS_LOG_NOTICE("[inserter] INFO: killing process.");
//     return 0;
// }

int bmt_init_dpdk_traffic_sampler(){
    //lock_guard<mutex> guard(cout_mutex);
    sai_status_t status;
    sai_attribute_t attr;

    /* create packet sampler */
    vector<sai_attribute_t> packetsampler_attrs;
    attr.id = SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE;
    attr.value.u32 = PACKETS_PER_SAMPLE;
    packetsampler_attrs.push_back(attr);

    attr.id = SAI_SAMPLEPACKET_ATTR_TYPE;
    attr.value.s32 = SAI_SAMPLEPACKET_TYPE_SLOW_PATH; // sample each packet
    packetsampler_attrs.push_back(attr);

    attr.id = SAI_SAMPLEPACKET_ATTR_MODE;
    attr.value.s32 = SAI_SAMPLEPACKET_MODE_EXCLUSIVE; // sample each packet
    packetsampler_attrs.push_back(attr);

    status = sai_samplepacket_api->create_samplepacket(&samplepacketOid,gSwitchId,(uint32_t)packetsampler_attrs.size(),packetsampler_attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("[inserter] Failed to create samplepacket, rv: %u", status);
        return (6);
    }
    SWSS_LOG_ERROR("[inserter] Created samplepacket");


    /* BIND to ingress dpdk port */
    attr.id = SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE;
    attr.value.oid=samplepacketOid;
    status = sai_port_api->set_port_attribute(dpdk_port,&attr);
    if (status != SAI_STATUS_SUCCESS){
        SWSS_LOG_ERROR("[inserter] Failed to bind packet sampler to port, rv: %u", status);
        return (5);   
    }
#if 0
    /* create hostif */
    vector<sai_attribute_t> hostif_attrs;
    attr.id = SAI_HOSTIF_ATTR_TYPE;
    attr.value.s32 = SAI_HOSTIF_TYPE_FD;
    hostif_attrs.push_back(attr);

    // attr.id = SAI_HOSTIF_ATTR_OPER_STATUS; // TODO, needed?
    // attr.value.booldata = true;
    // hostif_attrs.push_back(attr);

    //attr.id = SAI_HOSTIF_ATTR_QUEUE; 0 for now

    status = sai_hostif_api->create_hostif(&hostifOid,gSwitchId,(uint32_t)hostif_attrs.size(),hostif_attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("[inserter] Failed to create hostif, rv: %u", status);
        return (4);
    }
    SWSS_LOG_ERROR("[inserter] Created hostif");
#endif
    /* Use hostif created by portsorch */
    Port port;
    if (!gPortsOrch->getPort(dpdk_port, port))
    {
        SWSS_LOG_ERROR("[inserter] Failed to get hostif");
        return (4);
    }

    hostifOid = port.m_hif_id;
    SWSS_LOG_ERROR("[inserter] Got hostif");

    /* create trap group for samplepacket trap */
    vector<sai_attribute_t> hostifTrapGroup_attrs;
    // attr.id = SAI_HOSTIF_TRAP_GROUP_ATTR_QUEUE;
    // attr.value.u32 = 100; // TODO !
    // hostifTrapGroup_attrs.push_back(attr);
    // attr.id = SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER;
    status = sai_hostif_api->create_hostif_trap_group(&trapGroupOid,gSwitchId,(uint32_t)hostifTrapGroup_attrs.size(),hostifTrapGroup_attrs.data());
    if (status != SAI_STATUS_SUCCESS){
        SWSS_LOG_ERROR("[inserter] Failed to creat Hostif Trap group, rv:%d", status);
        return (3);
    }
    SWSS_LOG_ERROR("[inserter] Created hostif trap group");


	/* create trap for samplepacket action */
    vector<sai_attribute_t> trap_attrs;

    attr.id = SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE;
    attr.value.s32 = SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET;
    trap_attrs.push_back(attr);

    attr.id = SAI_HOSTIF_TRAP_ATTR_TRAP_GROUP;
    attr.value.oid = trapGroupOid;
    trap_attrs.push_back(attr);

    attr.id = SAI_HOSTIF_TRAP_ATTR_PACKET_ACTION;
    attr.value.s32 = SAI_PACKET_ACTION_LOG; //sai_packet_action_t
    trap_attrs.push_back(attr);

    attr.id = SAI_HOSTIF_TRAP_ATTR_TRAP_PRIORITY;
    attr.value.u32 = SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY + 5;
    trap_attrs.push_back(attr);

        //  TODO trap only dpdk port ingress
        // attr.id = SAI_HOSTIF_TRAP_ATTR_EXCLUDE_PORT_LIST;
        // attr.objlist.count = ;
        // attr.objlist.list  = ;

    status = sai_hostif_api->create_hostif_trap(&samplepackettrapOid, gSwitchId, (uint32_t)trap_attrs.size(), trap_attrs.data());
    if (status != SAI_STATUS_SUCCESS){
        SWSS_LOG_ERROR("[inserter] Failed to create samplepacket Hostif Trap, rv: %d", status);
        return (2);
    }
    SWSS_LOG_ERROR("[inserter] Created hostif samplepacket trap for action_log");

    /* create hostif table entry */
    vector<sai_attribute_t> hostif_table_entry_attrs;

    attr.id = SAI_HOSTIF_TABLE_ENTRY_ATTR_TYPE;
    attr.value.s32 = SAI_HOSTIF_TABLE_ENTRY_TYPE_TRAP_ID;
    hostif_table_entry_attrs.push_back(attr);

    attr.id = SAI_HOSTIF_TABLE_ENTRY_ATTR_TRAP_ID;
    attr.value.oid = samplepackettrapOid;
    hostif_table_entry_attrs.push_back(attr);

    attr.id = SAI_HOSTIF_TABLE_ENTRY_ATTR_CHANNEL_TYPE;
    attr.value.s32 = SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_NETDEV_PHYSICAL_PORT;
    hostif_table_entry_attrs.push_back(attr);
#if 0
    attr.id = SAI_HOSTIF_TABLE_ENTRY_ATTR_HOST_IF;
    attr.value.oid = hostifOid;
    hostif_table_entry_attrs.push_back(attr);
#endif

    status = sai_hostif_api->create_hostif_table_entry(
        &hostif_table_entryOid, gSwitchId, (uint32_t)hostif_table_entry_attrs.size(), hostif_table_entry_attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("[inserter] Failed to create default host interface table, rv: %d", status);
        return (1);
    }
    SWSS_LOG_ERROR("[inserter] Create default host interface table");


    SWSS_LOG_ERROR("[inserter] sampler init success.");
    return 0;
}



int bmt_deinit_dpdk_traffic_sampler(int init_status){
    //lock_guard<mutex> guard(cout_mutex);
    sai_status_t status = SAI_STATUS_SUCCESS;
    // TODO remove all entries / delete table and recreate with default entry only !!!!!!
    if (vhost_table.used_entries>0){
        for(uint32_t i=0; i<vhost_table.used_entries;i++){
// TODO
            // status = remove_table_vhost_entry(vhost_table.entry[i].entry_id);
            SWSS_LOG_ERROR("[inserter] deleting cache entries, free entries:");
            if (status != SAI_STATUS_SUCCESS)
                SWSS_LOG_ERROR("[inserter] Failed at remove_table_vhost_entry %u, status: %u", i, status);
        }

    }


    if (init_status<1){
        status = sai_hostif_api->remove_hostif_table_entry(hostif_table_entryOid);
        if (status != SAI_STATUS_SUCCESS)
            SWSS_LOG_ERROR("[inserter] Failed at remove_hostif_table_entry, rv %u", status);
    }

    if (init_status<2){
        status = sai_hostif_api->remove_hostif_trap(samplepackettrapOid);
        if (status != SAI_STATUS_SUCCESS)
            SWSS_LOG_ERROR("[inserter] Failed at remove_hostif_trap, rv %u", status);
    }

    if (init_status<3){
        status = sai_hostif_api->remove_hostif_trap_group(trapGroupOid);
        if (status != SAI_STATUS_SUCCESS)
            SWSS_LOG_ERROR("[inserter] Failed at remove_hostif_trap_group, rv %u", status);
    }

    if (init_status<4){
        status = sai_hostif_api->remove_hostif(hostifOid);
        if (status != SAI_STATUS_SUCCESS)
            SWSS_LOG_ERROR("[inserter] Failed at remove_hostif, rv %u", status);
    }

    if (init_status<5){
        sai_attribute_t attr;
        attr.id = SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE;
        attr.value.oid = SAI_NULL_OBJECT_ID;
        status = sai_port_api->set_port_attribute(dpdk_port,&attr);
        if (status != SAI_STATUS_SUCCESS)
            SWSS_LOG_ERROR("[inserter] Failed at samplepacket, rv %u", status);
    }   

    if (init_status<6){
        status = sai_samplepacket_api->remove_samplepacket(samplepacketOid);
        if (status != SAI_STATUS_SUCCESS)
            SWSS_LOG_ERROR("[inserter] Failed at samplepacket, rv %u", status);
    }   

    SWSS_LOG_ERROR("[inserter] sampler deinit success.");
    return 0;
}

/* call backs */
// void on_fdb_event(uint32_t count, sai_fdb_event_notification_data_t *data)
// {
//     cout << "on_fdb_event() invoked TODO implement" << endl;
//     // SWSS_LOG_ENTER();
//     // SWSS_LOG_NOTICE("TODO implement");
// }

// int create_sampler_socket(int* sockfd_p){
//     int sockopt;
//     struct ifreq ifopts;    /* set promiscuous mode */
//     char ifName[IFNAMSIZ];
    
//     /* Get interface name */
//     strcpy(ifName, DEFAULT_IF);

//     /* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
//     // if ((*sockfd_p = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
//     if ((*sockfd_p = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
//         perror("listener: socket"); 
//         return(SAI_STATUS_FAILURE);
//     }

//     /* Set interface to promiscuous mode - do we need to do this every time? */
//     strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
//     ioctl(*sockfd_p, SIOCGIFFLAGS, &ifopts);
//     ifopts.ifr_flags |= IFF_PROMISC;
//     ioctl(*sockfd_p, SIOCSIFFLAGS, &ifopts);
//     /* Allow the socket to be reused - incase connection is closed prematurely */
//     if (setsockopt(*sockfd_p, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
//         perror("setsockopt");
//         close(*sockfd_p);
//         return(SAI_STATUS_FAILURE);
//     }
//     /* Bind to device */
//     if (setsockopt(*sockfd_p, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ-1) == -1)  {
//         perror("SO_BINDTODEVICE");
//         close(*sockfd_p);
//         return(SAI_STATUS_FAILURE);
//     }
//     return (SAI_STATUS_SUCCESS);
// }

// void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // SWSS_LOG_NOTICE("packet recievd, of len %d", header->len);
// }

/* main */
int bmt_cache_inserter(void)
{
    // int sockfd;
    // we wait untill swss finish init - (runing async)
	sleep(60);
    /* get dpdk port */
    SWSS_LOG_NOTICE("[inserter] DEBUG: initialization started.");
    dpdk_port = sai_get_port_id_by_front_port((uint32_t) DPDK_FRONT_PORT); // TODO - take from bmtorcache

    SWSS_LOG_NOTICE("[inserter] DEBUG: found dpdk port.");
    /* init dpdk port trapping via acl*/
    int sampler_init_status = bmt_init_dpdk_traffic_sampler();
    SWSS_LOG_NOTICE("[inserter] DEBUG: sampler initialization finished. status: %d", sampler_init_status);
    if (sampler_init_status==0) { // only on init success    
        // int socket_status = create_sampler_socket(&sockfd);
        // SWSS_LOG_NOTICE("[inserter] DEBUG: samlper socket created. status: %d", socket_status);
        // if (socket_status==SAI_STATUS_SUCCESS) { // only on init success
        /* listen to traffic on dpdk port */
            // bmt_recv(sockfd); 
        // }
        pcap_t *handle;         /* Session handle */
        char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
        handle = pcap_open_live(DEFAULT_IF, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", DEFAULT_IF, errbuf);
            return(2);
        }
        pcap_loop(handle, 0, bmt_parse_packet, NULL);
        // close(sockfd);
    }
    /* deinit dpdk port trapping via acl*/
    SWSS_LOG_NOTICE("[inserter] DEBUG: dpdk listening done, deiniting:"); 
    int rc = bmt_deinit_dpdk_traffic_sampler(sampler_init_status);
    return(rc);

}

typedef struct _bmt_rule_evac_candidate_t{
    uint32_t offset;
    uint64_t read;
} bmt_rule_evac_candidate_t;

void bmt_cache_remove_rule(vector<bmt_rule_evac_candidate_t>* evac_candidates){
    lock_guard<mutex> guard(vhost_table.free_offset_mutex);
    uint32_t offset = (evac_candidates->back()).offset;
    evac_candidates->pop_back();
    SWSS_LOG_NOTICE( "[evac] INFO: cache evacuator freeing vhost table offset %d",offset);
    gBmToRCacheOrch->RemoveTableVhost(vhost_table.entry[offset].entry_id);
    vhost_table.free_offsets.push_back(offset);
}

void bmt_flush_cache(){
    // TODO - protect from removal of non existing entry?
    lock_guard<mutex> guard(vhost_table.free_offset_mutex);
    for (uint32_t i=0 ; i<vhost_table.used_entries ; i++){
        sai_bmtor_api->remove_table_vhost_entry(vhost_table.entry[i].entry_id);
    }
    vhost_table.used_entries = 0;
    vhost_table.free_offsets.clear();
    gFlushCache = false;
}

void counter_read_by_offset(uint32_t offset, uint64_t *counter) {
  sai_bmtor_stat_t counter_id = SAI_BMTOR_STAT_TABLE_VHOST_HIT_OCTETS;
  SWSS_LOG_NOTICE("reading vhost counter in offset %d", offset);
  sai_status_t status = sai_bmtor_api->get_bmtor_stats(vhost_table.entry[offset].entry_id, 1, &counter_id, counter);
  if (status)
    *counter = 0;
}

void bmt_cache_evacuator(){
    vector<bmt_rule_evac_candidate_t> evac_candidates;
    uint64_t counter_values[EVAC_BATCH_SIZE];
    uint64_t counter_diff[EVAC_BATCH_SIZE];
    bmt_rule_evac_candidate_t evac_candidate;
    uint32_t batch_start;
    uint32_t batch_end = 0;
    while (!gExitFlag){
        if (gFlushCache) bmt_flush_cache();
        if ( vhost_table.used_entries > (VHOST_TABLE_SIZE-2 )){ // 1 is default, 1 is to start before table is full
            if ( (vhost_table.free_offsets.size() < CACHE_EVAC_SIZE) && 
                 (evac_candidates.size() > 0) )
            {
                bmt_cache_remove_rule(&evac_candidates);
            }
                // TODO ADAPTIVE treshold
            if (evac_candidates.size() < CACHE_EVAC_SIZE)
            {
                batch_start = batch_end; 
                batch_end = (batch_start + EVAC_BATCH_SIZE)%VHOST_TABLE_SIZE;
                // seperate loops for constant read interval time.
                for (uint32_t i=batch_start ; i<batch_end; i++ ){
                    counter_read_by_offset(i, &counter_values[i-batch_start]);

                }
                sleep(1);
                for (uint32_t i=batch_start ; i<batch_end; i++ ){
                    counter_read_by_offset(i, &counter_diff[i-batch_start]);
                    // TODO - maybe devide by time interval to normalize.
                    counter_diff[i-batch_start] -= counter_values[i-batch_start];
                }
                for (uint32_t i=batch_start ; i<batch_end; i++ ){
                    SWSS_LOG_NOTICE("counter %d (bytes): 0x%lx", i, counter_diff[i-batch_start]);
                    if (counter_diff[i-batch_start] < EVAC_TRESH){
                        evac_candidate.offset = i;
                        evac_candidate.read = counter_diff[i-batch_start];
                        evac_candidates.push_back(evac_candidate);
                        SWSS_LOG_NOTICE("[evac] INFO: added evac candidate: offset: %d , counter delta: 0x%lx",i,counter_diff[i-batch_start]);
                    }
                }
            }
        }
    }
}

void bmt_cache_start() {
              thread t1_cache_inserter(bmt_cache_inserter);
              // thread t2_cache_evacuator(bmt_cache_evacuator);
              t1_cache_inserter.detach();
              // t2_cache_evacuator.detach();
}
 