#include <cassert>
#include <fstream>
#include <sstream>
#include <map>
#include <net/if.h>

#include "bmtorcacheorch.h"
#include "ipprefix.h"
#include "logger.h"
#include "swssnet.h"
#include "tokenize.h"

extern sai_object_id_t gVirtualRouterId;

// extern sai_router_interface_api_t*  sai_router_intfs_api;
// extern sai_route_api_t*             sai_route_api;
extern sai_bmtor_api_t*                sai_bmtor_api;
extern sai_switch_api_t*               sai_switch_api;
extern sai_port_api_t*                 sai_port_api;
extern sai_tunnel_api_t*               sai_tunnel_api;

extern PortsOrch *gPortsOrch;
extern sai_object_id_t gSwitchId;

BmToRCacheOrch::BmToRCacheOrch(DBConnector *db, vector<string> tableNames) :
        Orch(db, tableName)
{
    SWSS_LOG_ENTER();
    tunnel_created = false;
    gVtepIp = htonl(0x0a000014); // 10.0.0.20
    gVNI = 8;
    gVID = 120;
    // dpdk_port = 
}

sai_status_t BmToRCacheOrch::create_tunnel() {
    // Create tunnels and tunnel maps
  sai_status_t status;
  dpdk_port = sai_get_port_id_by_front_port(7);
  port_10_oid = sai_get_port_id_by_front_port(10);
  sai_attribute_t tunnel_map_attr[2];
  sai_object_id_t tunnel_encap_map;
  sai_object_id_t tunnel_decap_map;
  sai_object_id_t tunnel_encap_map_entry;
  sai_object_id_t tunnel_term_table_entry;
  tunnel_map_attr[0].id = SAI_TUNNEL_MAP_ATTR_TYPE;
  tunnel_map_attr[0].value.s32 = SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI;
  // tunnel_map_attr[0].value.s32 = SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI;
  tunnel_map_attr[1].id = SAI_TUNNEL_MAP_ATTR_MAP_TO_VALUE_LIST;
  tunnel_map_attr[1].value.tunnelmap.count = 0;
  status = sai_tunnel_api->create_tunnel_map(&tunnel_encap_map, gSwitchId, 2, tunnel_map_attr);
  SWSS_LOG_NOTICE("create_tunnel_map (encap). status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
    return status;

  tunnel_map_attr[0].id = SAI_TUNNEL_MAP_ATTR_TYPE;
  tunnel_map_attr[0].value.s32 = SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID;
  // tunnel_map_attr[0].value.s32 = SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF;
  tunnel_map_attr[1].id = SAI_TUNNEL_MAP_ATTR_MAP_TO_VALUE_LIST;
  tunnel_map_attr[1].value.tunnelmap.count = 0;
  status = sai_tunnel_api->create_tunnel_map(&tunnel_decap_map, gSwitchId, 2, tunnel_map_attr);
  SWSS_LOG_NOTICE("create_tunnel_map (decap). status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
    return status;

  sai_attribute_t tunnel_map_entry_attr[4];
  tunnel_map_entry_attr[0].id = SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE;
  // tunnel_map_entry_attr[0].value.s32 = SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI;
  tunnel_map_entry_attr[0].value.s32 = SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI;
  tunnel_map_entry_attr[1].id = SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP;
  tunnel_map_entry_attr[1].value.oid = tunnel_encap_map;
  tunnel_map_entry_attr[2].id = SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE;
  tunnel_map_entry_attr[2].value.u32 = gVNI;
  // tunnel_map_entry_attr[3].id = SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_KEY;
  // tunnel_map_entry_attr[3].value.oid = bridge_id;
  tunnel_map_entry_attr[3].id = SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_KEY;
  tunnel_map_entry_attr[3].value.oid = gVID;
  status = sai_tunnel_api->create_tunnel_map_entry(&tunnel_encap_map_entry, gSwitchId, 4, tunnel_map_entry_attr);
  SWSS_LOG_NOTICE("create_tunnel_map_entry (encap). status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
    return status;

  sai_attribute_t tunnel_attr[8];
  tunnel_attr[0].id = SAI_TUNNEL_ATTR_TYPE;
  tunnel_attr[0].value.s32 = SAI_TUNNEL_TYPE_VXLAN;
  tunnel_attr[1].id = SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE;
  tunnel_attr[1].value.oid = gUnderlayIfId;
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
  tunnel_attr[6].value.ipaddr.addr.ip4 = gVtepIp;
  status = sai_tunnel_api->create_tunnel(&gTunnelId, gSwitchId, 8, tunnel_attr);
  SWSS_LOG_NOTICE("create_tunnel. status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
    return status;

  // Create termination entry for host at switch vtep
  SWSS_LOG_NOTICE("sai_tunnel_id = 0x%lx\n", gTunnelId);
  sai_attribute_t tunnel_term_table_entry_attr[5];
  tunnel_term_table_entry_attr[0].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID;
  tunnel_term_table_entry_attr[0].value.oid = gVirtualRouterId;
  tunnel_term_table_entry_attr[1].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE;
  tunnel_term_table_entry_attr[1].value.s32 = SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2MP;
  tunnel_term_table_entry_attr[2].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP;
  tunnel_term_table_entry_attr[2].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
  tunnel_term_table_entry_attr[2].value.ipaddr.addr.ip4 = gVtepIp;
  tunnel_term_table_entry_attr[3].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID;
  tunnel_term_table_entry_attr[3].value.oid = gTunnelId;
  tunnel_term_table_entry_attr[4].id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE;
  tunnel_term_table_entry_attr[4].value.s32 = SAI_TUNNEL_TYPE_VXLAN;
  status = sai_tunnel_api->create_tunnel_term_table_entry(&tunnel_term_table_entry, gSwitchId, 5, tunnel_term_table_entry_attr);
  SWSS_LOG_NOTICE("create_tunnel_term_entry. status = %d\n", status);
  if (status != SAI_STATUS_SUCCESS)
    return status;
  tunnel_created = true;
  return SAI_STATUS_SUCCESS;
}

void BmToRCacheOrch::doTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    if (!gPortsOrch->isInitDone())
    {
        return;
    }

    string table_name = consumer.getTableName();
    if (table_name == "VNET_ROUTE_TUNNEL_TABLE") {
      doVnetRouteTunnelTask(consumer);
    } else if (table_name == "VNET_ROUTE_TABLE") {
      doVnetRouteTask(consumer);
    } else if (table_name == "VNET") {
      doVnetTask(consumer);
    } else if (table_name == "VNET_INTF") {
      doVnetIntfTask(consumer);
    } else if (table_name == "VXLAN_TUNNEL") {
      doVxlanTunnelTask(consumer);
    }
}

void BmToRCacheOrch::doVnetRouteTask(Consumer &consumer) {
  SWSS_LOG_ENTER();
  SWSS_LOG_NOTICE("doVnetRouteTask");
}

void BmToRCacheOrch::doVnetTask(Consumer &consumer) {
  SWSS_LOG_ENTER();
  SWSS_LOG_NOTICE("doVnetTask");
}

void BmToRCacheOrch::doVnetIntfTask(Consumer &consumer) {
  SWSS_LOG_ENTER();
  SWSS_LOG_NOTICE("doVnetIntfTask");
}

void BmToRCacheOrch::doVxlanTunnelTask(Consumer &consumer) {
  SWSS_LOG_ENTER();
  SWSS_LOG_NOTICE("doVxlanTunnelTask");
}

void BmToRCacheOrch::doVnetRouteTunnelTask(Consumer &consumer) {
    SWSS_LOG_ENTER();
    SWSS_LOG_NOTICE("doVnetRouteTunnelTask");
    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end()) {
        KeyOpFieldsValuesTuple t = it->second;
        vector<string> keys = tokenize(kfvKey(t), ':');
        string vnet_name(keys[0]);
        for (std::vector<string>::iterator it_keys = keys.begin(); it_keys < keys.end(); ++it_keys) {
            SWSS_LOG_NOTICE("keys[%d] = %s", (int) (it_keys - keys.begin()), it_keys->c_str());
        }
        string endpoint;
        IpPrefix overlay_dip_prefix(keys[keys.size()-1]);
        for (auto i : kfvFieldsValues(t)) {
            if (fvField(i) == "endpoint")
                endpoint = fvValue(i);
        }
        string op = kfvOp(t);
        uint32_t underlay_dip = 0;
        vector<string> dip_bytes = tokenize(endpoint, '.');
        for (vector<string>::iterator it_bytes = dip_bytes.begin(); it_bytes != dip_bytes.end(); ++it_bytes) {
            underlay_dip = underlay_dip << 8;
            underlay_dip += stoi(*it_bytes);
            SWSS_LOG_NOTICE("underlay_dip_wip = 0x%x. current byte = %s (0x%x)", underlay_dip, it_bytes->c_str(), stoi(*it_bytes));
        }
        uint16_t vnet_bitmap = 1 << 8; //TODO: build this from vnet peering list and vnet_intf
        if (op == SET_COMMAND) {
            sai_status_t status;
            dpdk_port = sai_get_port_id_by_front_port(7); // TODO remove
            port_10_oid = sai_get_port_id_by_front_port(10); // TODO remove
            SWSS_LOG_NOTICE("create VNET_ROUTE_TUNNEL_TABLE. gSwitchId = 0x%lx", gSwitchId);
            SWSS_LOG_NOTICE("vnet %s. enpoint %s", vnet_name.c_str(), endpoint.c_str());
            SWSS_LOG_NOTICE("underlay dst_ip 0x%x. vnet_bitmap 0x%x. overlay dip 0x%x", underlay_dip, vnet_bitmap, overlay_dip_prefix.getIp().getIp().ip_addr.ipv4_addr);
            SWSS_LOG_NOTICE("DPDK port 0x%lx", dpdk_port);
            SWSS_LOG_NOTICE("DPDK port (by alias): 0x%lx", sai_get_port_id_by_alias("Ethernet24"));

            if (!tunnel_created) {
                //TODO: return this once we fix sairedis bug
                // if (status != create_tunnel()) {
                //     SWSS_LOG_ERROR("Error creating VxLAN tunnel");
                //     throw "VxLAN tunnel creation failure";
                // }
            }

            sai_attribute_t table_peer_attr[4];
            table_peer_attr[0].id = SAI_TABLE_PEERING_ENTRY_ATTR_ACTION;
            table_peer_attr[0].value.s32 = SAI_TABLE_PEERING_ENTRY_ACTION_SET_VNET_BITMAP;
            table_peer_attr[1].id = SAI_TABLE_PEERING_ENTRY_ATTR_SRC_PORT;
            table_peer_attr[1].value.oid = port_10_oid;
            table_peer_attr[2].id = SAI_TABLE_PEERING_ENTRY_ATTR_META_REG;
            table_peer_attr[2].value.u16 = vnet_bitmap;
            status = bmtor_api->create_table_peering_entry(&peering_entry, g_switch_id, 4, table_peer_attr);
            printf("create_table_peering_entry. status = %d\n", status);
            if (status != SAI_STATUS_SUCCESS)
            {
              clear();
              return -1;
            }
            else
              peering_entry_created = true;

            sai_attribute_t vhost_table_entry_attr[8];
            vhost_table_entry_attr[0].id = SAI_TABLE_VHOST_ENTRY_ATTR_ACTION;
            vhost_table_entry_attr[0].value.s32 = SAI_TABLE_VHOST_ENTRY_ACTION_TO_PORT;
            vhost_table_entry_attr[1].id = SAI_TABLE_VHOST_ENTRY_ATTR_PORT_ID;
            vhost_table_entry_attr[1].value.oid = dpdk_port;
            vhost_table_entry_attr[2].id = SAI_TABLE_VHOST_ENTRY_ATTR_IS_DEFAULT;
            vhost_table_entry_attr[2].value.booldata = true;
            // Patch. TODO: need to add condition in header
            vhost_table_entry_attr[3].id = SAI_TABLE_VHOST_ENTRY_ATTR_PRIORITY; 
            vhost_table_entry_attr[3].value.u32 = 0;
            vhost_table_entry_attr[4].id = SAI_TABLE_VHOST_ENTRY_ATTR_META_REG_KEY;
            vhost_table_entry_attr[4].value.u32 = 0;
            vhost_table_entry_attr[5].id = SAI_TABLE_VHOST_ENTRY_ATTR_META_REG_MASK;
            vhost_table_entry_attr[5].value.u32 = 0;
            vhost_table_entry_attr[6].id = SAI_TABLE_VHOST_ENTRY_ATTR_DST_IP;
            vhost_table_entry_attr[6].value.u32 = 0;

            status = sai_bmtor_api->create_table_vhost_entry(&default_vhost_table_entry, gSwitchId, 7, vhost_table_entry_attr);
            if (status != SAI_STATUS_SUCCESS) {
                SWSS_LOG_ERROR("Failed to create table_vhost default entry");
                throw "BMToR initialization failure";
            }
        }
    }
}


sai_object_id_t
    BmToRCacheOrch::sai_get_port_id_by_front_port(uint32_t hw_port)
{
  sai_object_id_t new_objlist[32]; //TODO change back to getting from switch
  sai_attribute_t sai_attr;
  sai_attr.id = SAI_SWITCH_ATTR_PORT_NUMBER;
  // sai_switch_api->get_swi tch_attribute(switch_id, 1, &sai_attr);
  uint32_t max_ports = 32; //sai_attr.value.u32;

  sai_attr.id = SAI_SWITCH_ATTR_PORT_LIST;
  //sai_attr.value.objlist.list = (sai_object_id_t *) malloc(sizeof(sai_object_id_t) * max_ports);
  sai_attr.value.objlist.count = max_ports;
  sai_attr.value.objlist.list = &new_objlist[0];
  sai_switch_api->get_switch_attribute(gSwitchId, 1, &sai_attr);
  // SWSS_LOG_NOTICE("port list\n");

  sai_attribute_t hw_lane_list_attr;

  for (uint32_t i = 0; i < max_ports; i++)
  {
    uint32_t hw_port_list[4];
    hw_lane_list_attr.id = SAI_PORT_ATTR_HW_LANE_LIST;
    hw_lane_list_attr.value.u32list.list = &hw_port_list[0];
    hw_lane_list_attr.value.u32list.count = 4;
    // SWSS_LOG_NOTICE("port sai_object_id 0x%lx \n", sai_attr.value.objlist.list[i]);
    sai_port_api->get_port_attribute(sai_attr.value.objlist.list[i], 1,
                                 &hw_lane_list_attr);
    // SWSS_LOG_NOTICE("hw lanes: %d %d %d %d\n", hw_port_list[0], hw_port_list[1], hw_port_list[2], hw_port_list[3]);
    if (hw_port_list[0] == ((hw_port - 1) * 4)) // Front panel 1 is 0, 2 is 4, 3 is 8, etc.. (room is left for splits)
    {
      // free(hw_lane_list_attr.value.u32list.list);
      // free(sai_attr.value.objlist.list);
      return sai_attr.value.objlist.list[i];
    }
    // free(hw_lane_list_attr.value.u32list.list);
  }
  // free(sai_attr.value.objlist.list);
  SWSS_LOG_ERROR("Failed to get port %d sai_object_id", hw_port);
  throw "BMToR initialization failure";
  return -1;
}

sai_object_id_t BmToRCacheOrch::sai_get_port_id_by_alias(std::string alias) {
  Port port;
  gPortsOrch->getPort(alias, &port);
  switch (port.m_type) {
    case Port::PHY:
      return port.m_port_id;
    case Port::LAG:
      return port.m_lag_id;
    default:
      return SAI_NULL_OBJECT_ID;
  }
}

sai_object_id_t BmToRCacheOrch::getDPDKPort() {
  return dpdk_port;
}