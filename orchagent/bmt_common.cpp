#ifdef __cplusplus
extern "C" {
#endif
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <sairedis.h>
#ifdef __cplusplus
}
#endif
#include "bmt_common.h"
#include <csignal>
#include "logger.h"

// TODO move from main to here
extern sai_object_id_t gSwitchId;


extern sai_switch_api_t *sai_switch_api;
extern sai_port_api_t *sai_port_api;
extern sai_tunnel_api_t *sai_tunnel_api;
extern sai_vlan_api_t *sai_vlan_api;
extern sai_bridge_api_t *sai_bridge_api;
extern sai_bmtor_api_t *sai_bmtor_api;
sai_object_id_t tunnel_encap_map;
sai_object_id_t tunnel_decap_map;
sai_object_id_t tunnel_decap_map_entry;
sai_object_id_t tunnel_encap_map_entry;
sai_object_id_t tunnel_id;
sai_object_id_t tunnel_term_table_entry;
sai_object_id_t bridge_id;
sai_object_id_t vlan_oid;
sai_object_id_t vlan_member_oid;
sai_object_id_t dpdk_vlan_member_oid;
sai_object_id_t bridge_port_id;
sai_object_id_t dpdk_bridge_port_id;
sai_object_id_t vhost_table_entry;
sai_object_id_t default_vhost_table_entry;
sai_object_id_t peering_entry;
sai_object_id_t ports_to_bind[32];
sai_object_list_t ports_to_bind_list;
  
uint32_t vni = 8;
uint16_t vid = 120;
sai_object_id_t vr_id;
sai_object_id_t rif_id = 0x6; // loopback
sai_object_id_t port_10_oid;
sai_object_id_t dpdk_port; 
sai_object_id_t default_1q;


/**
*
*/
sai_object_id_t sai_get_port_id_by_front_port(uint32_t hw_port)
{
  SWSS_LOG_ERROR("%s enter", __FUNCTION__);
  sai_object_id_t new_objlist[32]; //TODO change back to getting from switch
  sai_attribute_t sai_attr;
  sai_attr.id = SAI_SWITCH_ATTR_PORT_NUMBER;
  // sai_switch_api->get_switch_attribute(switch_id, 1, &sai_attr);
  uint32_t max_ports = 32; //sai_attr.value.u32;

  sai_attr.id = SAI_SWITCH_ATTR_PORT_LIST;
  //sai_attr.value.objlist.list = (sai_object_id_t *) malloc(sizeof(sai_object_id_t) * max_ports);
  sai_attr.value.objlist.count = max_ports;
  sai_attr.value.objlist.list = &new_objlist[0];
  SWSS_LOG_ERROR("%s sw attr", __FUNCTION__);
  sai_switch_api->get_switch_attribute(gSwitchId, 1, &sai_attr);
  // printf("port list\n");

  sai_attribute_t hw_lane_list_attr;
  SWSS_LOG_ERROR("%s before loop", __FUNCTION__);

  for (unsigned int i = 0; i < max_ports; i++)
  {
    uint32_t hw_port_list[4];
    hw_lane_list_attr.id = SAI_PORT_ATTR_HW_LANE_LIST;
    hw_lane_list_attr.value.u32list.list = &hw_port_list[0];
    hw_lane_list_attr.value.u32list.count = 4;
    // printf("port sai_object_id 0x%" PRIx64 " \n", sai_attr.value.objlist.list[i]);
    sai_port_api->get_port_attribute(sai_attr.value.objlist.list[i], 1,
                                 &hw_lane_list_attr);
    // printf("hw lanes: %d %d %d %d\n", hw_port_list[0], hw_port_list[1], hw_port_list[2], hw_port_list[3]);
    if (hw_port_list[0] == ((hw_port - 1) * 4))
    {
      // free(hw_lane_list_attr.value.u32list.list);
      // free(sai_attr.value.objlist.list);
      return sai_attr.value.objlist.list[i];
    }
    // free(hw_lane_list_attr.value.u32list.list);
  }
  // free(sai_attr.value.objlist.list);
  printf("didn't find port");
  return -1;
}



void bmt_deinit(bmt_init_status_t* bmt_common_init)
{
  if (bmt_common_init->peering_entry_created)
  {
    printf("remove_table_peering_entry. status %d\n", sai_bmtor_api->remove_table_peering_entry(peering_entry));
  }
  if (bmt_common_init->vhost_table_entry_created)
  {
    printf("remove_table_vhost_entry. status %d\n", sai_bmtor_api->remove_table_vhost_entry(vhost_table_entry));
  }
  if (bmt_common_init->default_vhost_table_entry_created)
  {
    printf("remove_table_vhost_entry. status %d\n", sai_bmtor_api->remove_table_vhost_entry(default_vhost_table_entry));
  }
  if (bmt_common_init->tunnel_term_table_entry_created)
  {
    printf("remove_tunnel_term_table_entry. status %d\n", sai_tunnel_api->remove_tunnel_term_table_entry(tunnel_term_table_entry));
  }
  if (bmt_common_init->tunnel_created)
  {
    printf("remove_tunnel. status %d\n", sai_tunnel_api->remove_tunnel(tunnel_id));
  }
  if (bmt_common_init->tunnel_decap_map_entry_created)
  {
    printf("remove_tunnel_map_entry (decap). status %d\n", sai_tunnel_api->remove_tunnel_map_entry(tunnel_decap_map_entry));
  }
  if (bmt_common_init->tunnel_encap_map_entry_created)
  {
    printf("remove_tunnel_map_entry (encap). status %d\n", sai_tunnel_api->remove_tunnel_map_entry(tunnel_encap_map_entry));
  }
  if (bmt_common_init->tunnel_encap_map_created)
  {
    printf("remove_tunnel_map (encap). status %d\n", sai_tunnel_api->remove_tunnel_map(tunnel_encap_map));
  }
  if (bmt_common_init->tunnel_decap_map_created)
  {
    printf("remove_tunnel_map (decap). status %d\n", sai_tunnel_api->remove_tunnel_map(tunnel_decap_map));
  }
  if (bmt_common_init->vlan_member_created)
  {
    printf("remove_vlan_member. status %d\n", sai_vlan_api->remove_vlan_member(vlan_member_oid));
  }
  if (bmt_common_init->dpdk_vlan_member_created)
  {
    printf("remove_vlan_member. status %d\n", sai_vlan_api->remove_vlan_member(dpdk_vlan_member_oid));
  }
  if (bmt_common_init->vlan_created)
  {
    printf("remove_vlan. status %d\n", sai_vlan_api->remove_vlan(vlan_oid));
  }
  if (bmt_common_init->bridge_port_created)
  {
    sai_attribute_t bridge_port_attr;
    bridge_port_attr.id = SAI_BRIDGE_PORT_ATTR_ADMIN_STATE;
    bridge_port_attr.value.booldata = false;
    printf("set_bridge_port down. status %d\n", sai_bridge_api->set_bridge_port_attribute(bridge_port_id, &bridge_port_attr));
    //TODO: flush fdb entries, maybe?
    printf("remove_bridge_port. status %d\n", sai_bridge_api->remove_bridge_port(bridge_port_id));
    sai_attribute_t pvid_attr;
    pvid_attr.id = SAI_PORT_ATTR_PORT_VLAN_ID;
    pvid_attr.value.u16 = 1;
    printf("set pvid 1. status %d\n", sai_port_api->set_port_attribute(port_10_oid, &pvid_attr));
  }
  if (bmt_common_init->dpdk_bridge_port_created)
  {
    sai_attribute_t bridge_port_attr;
    bridge_port_attr.id = SAI_BRIDGE_PORT_ATTR_ADMIN_STATE;
    bridge_port_attr.value.booldata = false;
    printf("set_bridge_port down. status %d\n", sai_bridge_api->set_bridge_port_attribute(dpdk_bridge_port_id, &bridge_port_attr));
    //TODO: flush fdb entries, maybe?
    printf("remove_bridge_port. status %d\n", sai_bridge_api->remove_bridge_port(dpdk_bridge_port_id));
  }
  if (bmt_common_init->bridge_created)
  {
    printf("remove_bridge. status %d\n", sai_bridge_api->remove_bridge(bridge_id));
  }
  if (bmt_common_init->sai_ext_api_inited) {
    // TODO: no sai ext API 
    // printf("sai_extension_api_uninitialize. status %d\n", sai_ext_api_uninitialize(ports_to_bind_list));
  }
  sai_api_uninitialize();
}

int bmt_init(bmt_init_status_t* bmt_common_init)
{
  sai_status_t status;
  // Create 1D Bridge
  // sai_attribute_t bridge_attr[1];
  // bridge_attr[0].id = SAI_BRIDGE_ATTR_TYPE;
  // bridge_attr[0].value.s32 = SAI_BRIDGE_TYPE_1D;
  // status = sai_bridge_api->create_bridge(&bridge_id, gSwitchId, 1, bridge_attr);
  // printf("create_bridge. status = %d\n", status);
  // if (status != SAI_STATUS_SUCCESS)
  // {
  //   bmt_deinit();
  //   return -1;
  // }
  // else
  //   g_initbridge_created = true;

  sai_attribute_t bridge_port_attr[5];
  bridge_port_attr[0].id = SAI_BRIDGE_PORT_ATTR_TYPE;
  bridge_port_attr[0].value.s32 = SAI_BRIDGE_PORT_TYPE_PORT;
  bridge_port_attr[1].id = SAI_BRIDGE_PORT_ATTR_PORT_ID;
  bridge_port_attr[1].value.oid = port_10_oid;
  bridge_port_attr[2].id = SAI_BRIDGE_PORT_ATTR_BRIDGE_ID;
  bridge_port_attr[2].value.oid = default_1q;
  bridge_port_attr[3].id = SAI_BRIDGE_PORT_ATTR_ADMIN_STATE;
  bridge_port_attr[3].value.booldata = true;
  bridge_port_attr[4].id = SAI_BRIDGE_PORT_ATTR_VLAN_ID;
  bridge_port_attr[4].value.u16 = vid;
  status = sai_bridge_api->create_bridge_port(&bridge_port_id, gSwitchId, 5, bridge_port_attr);
  printf("create_bridge_port. status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
  {
    bmt_deinit(bmt_common_init);
    return -1;
  }
  else
    bmt_common_init->bridge_port_created = true;

  bridge_port_attr[0].id = SAI_BRIDGE_PORT_ATTR_TYPE;
  bridge_port_attr[0].value.s32 = SAI_BRIDGE_PORT_TYPE_PORT;
  bridge_port_attr[1].id = SAI_BRIDGE_PORT_ATTR_PORT_ID;
  bridge_port_attr[1].value.oid = dpdk_port;
  bridge_port_attr[2].id = SAI_BRIDGE_PORT_ATTR_BRIDGE_ID;
  bridge_port_attr[2].value.oid = default_1q;
  bridge_port_attr[3].id = SAI_BRIDGE_PORT_ATTR_ADMIN_STATE;
  bridge_port_attr[3].value.booldata = true;
  bridge_port_attr[4].id = SAI_BRIDGE_PORT_ATTR_VLAN_ID;
  bridge_port_attr[4].value.u16 = vid;
  status = sai_bridge_api->create_bridge_port(&dpdk_bridge_port_id, gSwitchId, 5, bridge_port_attr);
  printf("create_bridge_port. status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
  {
    bmt_deinit(bmt_common_init);
    return -1;
  }
  else
    bmt_common_init->dpdk_bridge_port_created = true;

  // Create Vlan and Vlan member
  sai_attribute_t vlan_attr[1];
  vlan_attr[0].id = SAI_VLAN_ATTR_VLAN_ID;
  vlan_attr[0].value.u16 = vid;
  status = sai_vlan_api->create_vlan(&vlan_oid, gSwitchId, 1, vlan_attr);
  printf("create_vlan. status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
    bmt_deinit(bmt_common_init);
  else
    bmt_common_init->vlan_created = true;

  sai_attribute_t vlan_member_attr[3];
  vlan_member_attr[0].id = SAI_VLAN_MEMBER_ATTR_VLAN_ID;
  vlan_member_attr[0].value.oid = vlan_oid;
  vlan_member_attr[1].id = SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE;
  vlan_member_attr[1].value.s32 = SAI_VLAN_TAGGING_MODE_UNTAGGED;
  vlan_member_attr[2].id = SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID;
  vlan_member_attr[2].value.oid = bridge_port_id;
  status = sai_vlan_api->create_vlan_member(&vlan_member_oid, gSwitchId, 3, vlan_member_attr);
  printf("create_vlan_member. status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
    bmt_deinit(bmt_common_init);
  else
    bmt_common_init->vlan_member_created = true;

  vlan_member_attr[0].id = SAI_VLAN_MEMBER_ATTR_VLAN_ID;
  vlan_member_attr[0].value.oid = vlan_oid;
  vlan_member_attr[1].id = SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE;
  vlan_member_attr[1].value.s32 = SAI_VLAN_TAGGING_MODE_TAGGED;
  vlan_member_attr[2].id = SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID;
  vlan_member_attr[2].value.oid = dpdk_bridge_port_id;
  status = sai_vlan_api->create_vlan_member(&dpdk_vlan_member_oid, gSwitchId, 3, vlan_member_attr);
  printf("create_vlan_member. status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
    bmt_deinit(bmt_common_init);
  else
    bmt_common_init->dpdk_vlan_member_created = true;

  sai_attribute_t pvid_attr;
  pvid_attr.id = SAI_PORT_ATTR_PORT_VLAN_ID;
  pvid_attr.value.u16 = vid;
  status = sai_port_api->set_port_attribute(port_10_oid, &pvid_attr);
  printf("set pvid. status = %d\n", status);
  

  // Create tunnels and tunnel maps
  sai_attribute_t tunnel_map_attr[2];
  // sai_tunnel_map_t encap_map = { .value.vni_id = vni, .key}
  tunnel_map_attr[0].id = SAI_TUNNEL_MAP_ATTR_TYPE;
  tunnel_map_attr[0].value.s32 = SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI;
  tunnel_map_attr[1].id = SAI_TUNNEL_MAP_ATTR_MAP_TO_VALUE_LIST;
  tunnel_map_attr[1].value.tunnelmap.count = 0;
  status = sai_tunnel_api->create_tunnel_map(&tunnel_encap_map, gSwitchId, 2, tunnel_map_attr);
  printf("create_tunnel_map (encap). status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
  {
    bmt_deinit(bmt_common_init);
    return -1;
  }
  else
    bmt_common_init->tunnel_encap_map_created = true;

  tunnel_map_attr[0].id = SAI_TUNNEL_MAP_ATTR_TYPE;
  tunnel_map_attr[0].value.s32 = SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID;
  tunnel_map_attr[1].id = SAI_TUNNEL_MAP_ATTR_MAP_TO_VALUE_LIST;
  tunnel_map_attr[1].value.tunnelmap.count = 0;
  status = sai_tunnel_api->create_tunnel_map(&tunnel_decap_map, gSwitchId, 2, tunnel_map_attr);
  printf("create_tunnel_map (decap). status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
  {
    bmt_deinit(bmt_common_init);
    return -1;
  }
  else
    bmt_common_init->tunnel_decap_map_created = true;

  sai_attribute_t tunnel_map_entry_attr[4];
  tunnel_map_entry_attr[0].id = SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE;
  tunnel_map_entry_attr[0].value.s32 = SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI;
  tunnel_map_entry_attr[1].id = SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP;
  tunnel_map_entry_attr[1].value.oid = tunnel_encap_map;
  tunnel_map_entry_attr[2].id = SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE;
  tunnel_map_entry_attr[2].value.u32 = vni;
  tunnel_map_entry_attr[3].id = SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_KEY;
  tunnel_map_entry_attr[3].value.u16 = vid;
  status = sai_tunnel_api->create_tunnel_map_entry(&tunnel_encap_map_entry, gSwitchId, 4, tunnel_map_entry_attr);
  printf("create_tunnel_map_entry (encap). status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
  {
    bmt_deinit(bmt_common_init);
    return -1;
  }
  else
    bmt_common_init->tunnel_encap_map_entry_created = true;

  tunnel_map_entry_attr[0].id = SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE;
  tunnel_map_entry_attr[0].value.s32 = SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID;
  tunnel_map_entry_attr[1].id = SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP;
  tunnel_map_entry_attr[1].value.oid = tunnel_decap_map;
  tunnel_map_entry_attr[2].id = SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY;
  tunnel_map_entry_attr[2].value.u32 = vni;
  tunnel_map_entry_attr[3].id = SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_VALUE;
  tunnel_map_entry_attr[3].value.u16 = vid;
  // status = sai_tunnel_api->create_tunnel_map_entry(&tunnel_decap_map_entry, gSwitchId, 4, tunnel_map_entry_attr);
  // printf("create_tunnel_map_entry (decap). status = %d\n", status);
  // if (status != SAI_STATUS_SUCCESS)
  // {
  //   bmt_deinit();
  //   return -1;
  // }
  // else
  //   g_inittunnel_decap_map_entry_created = true;

  sai_ip4_t switch_vtep_ip = htonl(0x0a000014); // 10.0.0.20
  sai_attribute_t tunnel_attr[8];
  tunnel_attr[0].id = SAI_TUNNEL_ATTR_TYPE;
  tunnel_attr[0].value.s32 = SAI_TUNNEL_TYPE_VXLAN;
  tunnel_attr[1].id = SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE;
  tunnel_attr[1].value.oid = rif_id;
  tunnel_attr[2].id = SAI_TUNNEL_ATTR_OVERLAY_INTERFACE;
  tunnel_attr[2].value.oid = port_10_oid;
  tunnel_attr[3].id = SAI_TUNNEL_ATTR_ENCAP_TTL_MODE;
  tunnel_attr[3].value.s32 = SAI_TUNNEL_TTL_MODE_PIPE_MODEL;
  tunnel_attr[7].id = SAI_TUNNEL_ATTR_DECAP_TTL_MODE;
  tunnel_attr[7].value.s32 = SAI_TUNNEL_TTL_MODE_PIPE_MODEL;
  tunnel_attr[4].id = SAI_TUNNEL_ATTR_ENCAP_MAPPERS;
  tunnel_attr[4].value.objlist.count = 1;
  tunnel_attr[4].value.objlist.list = &tunnel_encap_map;
  tunnel_attr[5].id = SAI_TUNNEL_ATTR_DECAP_MAPPERS;
  tunnel_attr[5].value.objlist.count = 1;
  tunnel_attr[5].value.objlist.list = &tunnel_decap_map;
  tunnel_attr[6].id = SAI_TUNNEL_ATTR_ENCAP_SRC_IP;
  tunnel_attr[6].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
  tunnel_attr[6].value.ipaddr.addr.ip4 = switch_vtep_ip;
  status = sai_tunnel_api->create_tunnel(&tunnel_id, gSwitchId, 8, tunnel_attr);
  printf("create_tunnel. status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
  {
    bmt_deinit(bmt_common_init);
    return -1;
  }
  else
    bmt_common_init->tunnel_created = true;

  // Create termination entry for host at switch vtep
  printf("sai_tunnel_id = 0x%" PRIx64 "\n", tunnel_id);
  sai_attribute_t tunnel_term_table_entry_attr[5];
  tunnel_term_table_entry_attr[0].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID;
  tunnel_term_table_entry_attr[0].value.oid = vr_id;
  tunnel_term_table_entry_attr[1].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE;
  tunnel_term_table_entry_attr[1].value.s32 = SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2MP;
  tunnel_term_table_entry_attr[2].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP;
  tunnel_term_table_entry_attr[2].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
  tunnel_term_table_entry_attr[2].value.ipaddr.addr.ip4 = switch_vtep_ip;
  tunnel_term_table_entry_attr[3].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID;
  tunnel_term_table_entry_attr[3].value.oid = tunnel_id;
  tunnel_term_table_entry_attr[4].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE;
  tunnel_term_table_entry_attr[4].value.s32 = SAI_TUNNEL_TYPE_VXLAN;
  status = sai_tunnel_api->create_tunnel_term_table_entry(&tunnel_term_table_entry, gSwitchId, 5, tunnel_term_table_entry_attr);
  printf("create_tunnel_term_entry. status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
  {
    bmt_deinit(bmt_common_init);
    return -1;
  }
  else
  	bmt_common_init->tunnel_term_table_entry_created = true;

  uint16_t vnet_bitmap = 1 << 8;
  sai_attribute_t table_peer_attr[4];
  table_peer_attr[0].id = SAI_TABLE_PEERING_ENTRY_ATTR_ACTION;
  table_peer_attr[0].value.s32 = SAI_TABLE_PEERING_ENTRY_ACTION_SET_VNET_BITMAP;
  table_peer_attr[1].id = SAI_TABLE_PEERING_ENTRY_ATTR_SRC_PORT;
  table_peer_attr[1].value.oid = port_10_oid;
  table_peer_attr[2].id = SAI_TABLE_PEERING_ENTRY_ATTR_META_REG;
  table_peer_attr[2].value.u16 = vnet_bitmap;
  status = sai_bmtor_api->create_table_peering_entry(&peering_entry, gSwitchId, 4, table_peer_attr);
  printf("create_table_peering_entry. status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
  {
    bmt_deinit(bmt_common_init);
    return -1;
  }
  else
    bmt_common_init->peering_entry_created = true;

  sai_attribute_t vhost_table_entry_attr[7];
  // uint32_t overlay_dip =  0xc0a81401; //192.168.20.1
  vhost_table_entry_attr[0].id = SAI_TABLE_VHOST_ENTRY_ATTR_ACTION;
  vhost_table_entry_attr[0].value.s32 = SAI_TABLE_VHOST_ENTRY_ACTION_TO_PORT;
  vhost_table_entry_attr[1].id = SAI_TABLE_VHOST_ENTRY_ATTR_PORT_ID;
  vhost_table_entry_attr[1].value.oid = dpdk_port;
  vhost_table_entry_attr[2].id = SAI_TABLE_VHOST_ENTRY_ATTR_IS_DEFAULT;
  vhost_table_entry_attr[2].value.booldata = true;
  status = sai_bmtor_api->create_table_vhost_entry(&default_vhost_table_entry, gSwitchId, 3, vhost_table_entry_attr);
  printf("create_table_vhost_entry. status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
  {
    bmt_deinit(bmt_common_init);
    return -1;
  }
  else
    bmt_common_init->default_vhost_table_entry_created = true;
  return 0;
}
