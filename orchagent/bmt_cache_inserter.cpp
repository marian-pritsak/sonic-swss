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
#include "bmt_orch_constants.h"
#include "bmt_common.h"
#include "bmt_cache_inserter.h"
#include "logger.h"
#include <unistd.h>
#include <string.h>
#include "portsorch.h"

using namespace std;
extern sai_hostif_api_t *sai_hostif_api;
extern sai_samplepacket_api_t *sai_samplepacket_api;
extern sai_port_api_t *sai_port_api;
extern sai_switch_api_t *sai_switch_api;
extern sai_bmtor_api_t *sai_bmtor_api;

//mutex cout_mutex;
extern PortsOrch *gPortsOrch;

typedef struct bmt_dpdk_pkt_t {
    sai_object_id_t trap_id; // TODO check if needed.
    sai_object_id_t in_port; // just checking to be dpdk exclusive.
    sai_object_id_t in_lag; // just checking to be dpdk exclusive.
    uint32_t underlay_dip;
    uint32_t overlay_dip;
    uint32_t vni;
    sai_object_id_t rule;
} bmt_dpdk_pkt_t;

typedef struct bmt_vhost_entry_t {
    sai_object_id_t entry_id;
    uint32_t overlay_dip;
    uint32_t underlay_dip;
    uint16_t port_vect;
    sai_object_id_t tunnel_id;
}bmt_vhost_entry_t;


typedef struct bmt_vhost_table_t {
    sai_object_id_t     Oid;
    bmt_vhost_entry_t   entry[VHOST_TABLE_SIZE];
    uint32_t            used_entries=0;
    mutex               free_offset_mutex;
    vector<uint32_t>    free_offsets; // TODO implement cache evac
} bmt_vhost_table_t;

// typedef struct rules_db_t {

// } rules_db_t;

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

sai_status_t bmt_parse_packet(uint8_t* buffer, sai_size_t buffer_size, uint32_t attr_count, sai_attribute_t sai_packet_attr[3], bmt_dpdk_pkt_t *pkt){
    // omers: assuming vlan(for encoding inport log) + ipv4.
    /* parse trap packet attr */
    lock_guard<mutex> guard(vhost_table.free_offset_mutex);
    SWSS_LOG_ERROR("marianp ===============================================================");
    SWSS_LOG_ERROR("marianp [recv] Packet recv info:");
    for (int i =0 ; i<3 ; i++){
        switch (sai_packet_attr[i].id) {
            case SAI_HOSTIF_PACKET_ATTR_HOSTIF_TRAP_ID:
                pkt->trap_id = sai_packet_attr[i].value.oid;
                break;
            case SAI_HOSTIF_PACKET_ATTR_INGRESS_PORT:
                pkt->in_port = sai_packet_attr[i].value.oid;
                break;
            case SAI_HOSTIF_PACKET_ATTR_INGRESS_LAG:
                pkt->in_lag = sai_packet_attr[i].value.oid;
                break;
            default:
                SWSS_LOG_ERROR("fd packet attr was not parsed, id: %u ,value: 0x%lx", sai_packet_attr[i].id, sai_packet_attr[i].value.oid);
                return (SAI_STATUS_FAILURE);
        }
    }
    SWSS_LOG_ERROR("trap oid: 0x%lx", pkt->trap_id);
    SWSS_LOG_ERROR("Packet size: %lu", buffer_size);

    uint16_t etherType[3];
    uint8_t inner_ipv4_ver;
    uint8_t outer_ipv4_ver;
    if (buffer_size >= 84){ // TODO should be 84
        etherType[0] = (uint16_t)(((uint16_t)buffer[12]<<8)|(uint16_t)buffer[13]); // outer etherType (tagged)
        etherType[1] = (uint16_t)(((int)buffer[16]<<8U)|(int)buffer[17]); // Vlan etherType
        etherType[2] = (uint16_t)(((int)buffer[62]<<8)|(int)buffer[63]); // inner etherType
        outer_ipv4_ver = (uint8_t)(buffer[18]>>3);
        inner_ipv4_ver = (uint8_t)(buffer[64]>>3);
        

        if(
            etherType[0] == TYPE_VLAN &&
            etherType[1] == TYPE_IPV4 &&
            etherType[2] == TYPE_IPV4 &&
            outer_ipv4_ver == 4 &&
            inner_ipv4_ver == 4
        )
        {
            pkt->vni = (((uint16_t)buffer[14]>>4)<<8)|buffer[15];
            pkt->underlay_dip = ((uint32_t)buffer[34]<<24) | ((uint32_t)buffer[35]<<16) | ((uint32_t)buffer[36]<<8) | ((uint32_t)buffer[37]); 
            pkt->overlay_dip = ((uint32_t)buffer[80]<<24) | ((uint32_t)buffer[81]<<16) | ((uint32_t)buffer[82]<<8) | ((uint32_t)buffer[83]); 
            SWSS_LOG_ERROR("packet parsed successfully:");
            //SWSS_LOG_ERROR("   underlay ip="<< buffer[34]<< "."<< buffer[35]<< "."<< buffer[36]<< "."<< buffer[37]<< endl;
            //SWSS_LOG_ERROR("   overlay  ip="<< buffer[80]<< "."<< buffer[81]<< "."<< buffer[82]<< "."<< buffer[83]<< endl;
            //SWSS_LOG_ERROR("   vid= "<< pkt->vni << endl;
        }
        else{
            SWSS_LOG_ERROR("Bad parse / not vlan ipv4 packet"); 
            //cout << "   outer L2    etherType: 0x"<< hex << etherType[0] << endl;
            //cout << "   vlan        etherType: 0x"<< hex << etherType[1] << endl;
            //cout << "   inner L2    etherType: 0x"<< hex << etherType[2] << endl;
            //cout << "   outer_ipv4_ver: "<< dec << outer_ipv4_ver <<endl;
            //cout << "   inner_ipv4_ver: "<< dec << inner_ipv4_ver <<endl;
            //cout << "   Packet content:" << endl;
            //for (uint8_t i=0; i<buffer_size;i++){
            //    if (i and (0 == i % 16)){cout << endl;}
            //    cout << hex << buffer[i];
            //}
            //cout << dec << endl;
        }
    }
    else{
        SWSS_LOG_ERROR("packet too short: %lu bytes, expecting 84 bytes", buffer_size);
        return (SAI_STATUS_FAILURE);
    }
    SWSS_LOG_ERROR("===============================================================");
    return (SAI_STATUS_SUCCESS);
}

sai_status_t bmt_get_free_offset(uint32_t* offset_ptr){
    if (vhost_table.used_entries > (VHOST_TABLE_SIZE-2)){
        //TODO take from free list when cache evac is working.
        lock_guard<mutex> guard(vhost_table.free_offset_mutex);
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

sai_status_t bmt_get_port_vect_from_vni(uint32_t vni, uint16_t* port_vect){
    // TODO implement
    *port_vect = (uint16_t) 0xfff;
    return SAI_STATUS_SUCCESS;
}

sai_status_t bmt_cache_insert_vhost_entry(uint16_t port_vect, uint32_t overlay_dip, uint32_t underlay_dip, sai_object_id_t tunnel_id){

    uint32_t offset;
    sai_status_t status = bmt_get_free_offset(&offset);
    if (status != SAI_STATUS_SUCCESS){ return status; }

    sai_attribute_t attr[7];
    // TODO can be defined as a global to save time for those fixed arributes, and change only few attrs.
    attr[0].id = SAI_TABLE_PEERING_ENTRY_ATTR_ACTION;
    attr[0].value.s32 = SAI_TABLE_VHOST_ENTRY_ACTION_TO_TUNNEL; 

    attr[1].id = SAI_TABLE_VHOST_ENTRY_ATTR_PRIORITY;
    attr[1].value.u32 = offset;

    attr[2].id = SAI_TABLE_VHOST_ENTRY_ATTR_META_REG_KEY;
    attr[2].value.u16 = 0x0000;

    attr[3].id = SAI_TABLE_VHOST_ENTRY_ATTR_META_REG_MASK;
    attr[3].value.u16 = 0x0fff & ~port_vect;

    attr[4].id = SAI_TABLE_VHOST_ENTRY_ATTR_DST_IP;
    attr[4].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
    attr[4].value.ipaddr.addr.ip4 = htonl(overlay_dip);

    attr[5].id = SAI_TABLE_VHOST_ENTRY_ATTR_UNDERLAY_DIP;
    attr[5].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
    attr[5].value.ipaddr.addr.ip4 = htonl(underlay_dip);

    attr[6].id = SAI_TABLE_VHOST_ENTRY_ATTR_TUNNEL_ID;
    attr[6].value.oid = tunnel_id;

	// TODO - ???? 
    (void)attr;
    // sai_status_t status = sai_ext_bmtor->sai_create_table_vhost_entry(&vhost_table.entry[offset].entry_id,gSwitchId,7,attr);
    if (status != SAI_STATUS_SUCCESS){
        SWSS_LOG_ERROR("[inserter] ERROR: failed to insert vhost rule, rv: %u", status);
        return status;
    }

    vhost_table.entry[offset].overlay_dip = overlay_dip;
    vhost_table.entry[offset].underlay_dip = underlay_dip;
    vhost_table.entry[offset].port_vect = port_vect;
    vhost_table.entry[offset].tunnel_id = tunnel_id;
    
    return SAI_STATUS_SUCCESS;
}

/* receive flow */
int bmt_recv(){
    SWSS_LOG_ERROR("[inserter] starting recive channel");
    uint8_t buffer[CONTROL_MTU] ; 
    sai_size_t buffer_size;
    uint32_t attr_count;
    sai_attribute_t sai_packet_attr[3];
    sai_status_t status;
    bmt_dpdk_pkt_t pkt;

    while(gScanDpdkPort)
    { 
        SWSS_LOG_ERROR("[inserter] listening...");
        attr_count = 3;
        buffer_size = CONTROL_MTU;
        status = sai_hostif_api->recv_hostif_packet(hostifOid, buffer, &buffer_size, &attr_count, sai_packet_attr);
        sleep(5);
        if (status != SAI_STATUS_SUCCESS){
            SWSS_LOG_ERROR("[inserter] ERROR: BMtor_dpdk_sampler :  sai_recv_hostif_packet , status %d", status);
            continue;
        }
        status = bmt_parse_packet(buffer, buffer_size, attr_count, sai_packet_attr,&pkt);
        if (status != SAI_STATUS_SUCCESS){
            SWSS_LOG_ERROR("[inserter] ERROR: BMtor_dpdk_sampler :  bmt_parse_packet , status %d", status);
            continue;

	// TODO - fix parsing
        uint16_t port_vect = 0; //??
	sai_object_id_t tunnel_id = 0; //??
        status = bmt_cache_insert_vhost_entry(port_vect, pkt.overlay_dip, pkt.underlay_dip, tunnel_id);
        }
    }
    SWSS_LOG_ERROR("[inserter] INFO: killing process.");
    return 0;
}

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


/* helper functions */
/*
sai_object_id_t sai_get_port_id_by_front_port(uint32_t hw_port) {
    cout << "[inserter] sai_get_port_id_by_front_port" << endl;
    sai_object_id_t new_objlist[32]; //TODO change back to getting from switch
    sai_attribute_t sai_attr;
    sai_attr.id = SAI_SWITCH_ATTR_PORT_NUMBER;
    // switch_api->get_switch_attribute(switch_id, 1, &sai_attr);
    uint32_t max_ports = 32; //sai_attr.value.u32;

    sai_attr.id = SAI_SWITCH_ATTR_PORT_LIST;
    //sai_attr.value.objlist.list = (sai_object_id_t *) malloc(sizeof(sai_object_id_t) * max_ports);
    sai_attr.value.objlist.count = max_ports;
    sai_attr.value.objlist.list = &new_objlist[0];
    sai_switch_api.get_switch_attribute(gSwitchId, 1, &sai_attr);
    printf("[inserter] port list\n");

    sai_attribute_t hw_lane_list_attr;

    for (uint32_t i = 0; i < max_ports; i++) {
        uint32_t hw_port_list[4];
        hw_lane_list_attr.id = SAI_PORT_ATTR_HW_LANE_LIST;
        hw_lane_list_attr.value.u32list.list = &hw_port_list[0];
        hw_lane_list_attr.value.u32list.count = 4;
        cout << "[inserter] port sai_object_id " << sai_attr.value.objlist.list[i] << endl;
        sai_port_api.get_port_attribute(sai_attr.value.objlist.list[i], 1,
                                        &hw_lane_list_attr);
        printf("[inserter] hw lanes: %d %d %d %d\n", hw_port_list[0], hw_port_list[1], hw_port_list[2], hw_port_list[3]);
        if (hw_port_list[0] == ((hw_port - 1) * 4)) {
            // free(hw_lane_list_attr.value.u32list.list);
            // free(sai_attr.value.objlist.list);
            return sai_attr.value.objlist.list[i];
        }
    // free(hw_lane_list_attr.value.u32list.list);
    }
    // free(sai_attr.value.objlist.list);
    cout << "[inserter] ERROR didn't find port" << endl;
    return -1;
}

*/

/* main */
int bmt_cache_inserter(void)
{
	sleep(60);
    /* get dpdk port */
    SWSS_LOG_ERROR("[inserter] DEBUG: initialization started.");
    dpdk_port = sai_get_port_id_by_front_port((uint32_t) DPDK_FRONT_PORT);

    SWSS_LOG_ERROR("[inserter] DEBUG: found dpdk port.");
    /* init dpdk port trapping via acl*/
    int sampler_init_status = bmt_init_dpdk_traffic_sampler();
    SWSS_LOG_ERROR("[inserter] DEBUG: initialization finished. status: %d", sampler_init_status);

    /* listen to traffic on dpdk port */
    if (sampler_init_status==0) { // only on init success
        bmt_recv(); 
    }
    /* deinit dpdk port trapping via acl*/
    SWSS_LOG_ERROR("[inserter] DEBUG: dpdk listening done, deiniting:"); 
    int rc = bmt_deinit_dpdk_traffic_sampler(sampler_init_status);
    return(rc);

}


int bmt_cache_evacuator(void){
	while (gScanDpdkPort){
		if ((vhost_table.used_entries > (VHOST_TABLE_SIZE-2)) && vhost_table.free_offsets.size()<CACHE_EVAC_SIZE){
			// TODO loop over all entries, read counters and catch the mice flows
			// TODO remove mice entry
			lock_guard<mutex> guard(vhost_table.free_offset_mutex);
			uint32_t offset = 0;
			SWSS_LOG_ERROR("INFO: cache evacuator freeing vhost table offset %u", offset);
			sai_bmtor_api->remove_table_vhost_entry(vhost_table.entry[offset].entry_id);
			vhost_table.free_offsets.push_back(offset);
		}
		
	}
	return 0;
}

void bmt_cache_start() {
              thread t1_cache_inserter(bmt_cache_inserter);
              //thread t2_cache_evacuator(bmt_cache_evacuator);
              t1_cache_inserter.detach();
              //t2_cache_evacuator.detach();
}
