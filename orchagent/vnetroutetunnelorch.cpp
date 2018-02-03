#include <cassert>
#include <fstream>
#include <sstream>
#include <map>
#include <net/if.h>

#include "vnetroutetunnelorch.h"
#include "ipprefix.h"
#include "logger.h"
#include "swssnet.h"
#include "tokenize.h"

extern sai_object_id_t gVirtualRouterId;

// extern sai_router_interface_api_t*  sai_router_intfs_api;
// extern sai_route_api_t*             sai_route_api;
extern sai_bmtor_api_t*                sai_bmtor_api;

extern PortsOrch *gPortsOrch;
extern sai_object_id_t gSwitchId;

VnetRouteTunnelOrch::VnetRouteTunnelOrch(DBConnector *db, string tableName) :
        Orch(db, tableName)
{
    SWSS_LOG_ENTER();
}

// sai_object_id_t VnetRouteTunnelOrch::getRouterIntfsId(const string &alias)
// {
//     Port port;
//     gPortsOrch->getPort(alias, port);
//     assert(port.m_rif_id);
//     return port.m_rif_id;
// }

// void VnetRouteTunnelOrch::increaseRouterIntfsRefCount(const string &alias)
// {
//     SWSS_LOG_ENTER();

//     m_syncdIntfses[alias].ref_count++;
//     SWSS_LOG_DEBUG("Router interface %s ref count is increased to %d",
//                   alias.c_str(), m_syncdIntfses[alias].ref_count);
// }

// void VnetRouteTunnelOrch::decreaseRouterIntfsRefCount(const string &alias)
// {
//     SWSS_LOG_ENTER();

//     m_syncdIntfses[alias].ref_count--;
//     SWSS_LOG_DEBUG("Router interface %s ref count is decreased to %d",
//                   alias.c_str(), m_syncdIntfses[alias].ref_count);
// }

void VnetRouteTunnelOrch::doTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    if (!gPortsOrch->isInitDone())
    {
        return;
    }

    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;

        vector<string> keys = tokenize(kfvKey(t), ':');
        string vnet_name(keys[0]);
        string endpoint;
        IpPrefix ip_prefix(kfvKey(t).substr(kfvKey(t).find(':')+1));
        for (auto i : kfvFieldsValues(t)) {
            if (fvField(i) == "endpoint")
                endpoint = fvValue(i);
        }
        string op = kfvOp(t);
        uint32_t underlay_dip = 0;
        vector<string> dip_bytes = tokenize(endpoint, ':');
        for (vector<string>::iterator it = dip_bytes.begin(); it != dip_bytes.end(); ++it) {
            underlay_dip = underlay_dip << 8;
            underlay_dip += stoi(*it);
        }
        uint16_t vnet_bitmap = 1 << 3; //TODO: build this from vnet peering list and vnet_intf
        if (op == SET_COMMAND)
        {
            SWSS_LOG_NOTICE("create VNET_ROUTE_TUNNEL_TABLE. gSwitchId = 0x%lx", gSwitchId);
            SWSS_LOG_NOTICE("vnet %s. enpoint %s", vnet_name.c_str(), endpoint.c_str());
            SWSS_LOG_NOTICE("dst_ip 0x%x", underlay_dip);

            sai_object_id_t vhost_table_entry;
            sai_attribute_t vhost_table_entry_attr[7];
            vhost_table_entry_attr[0].id = SAI_TABLE_VHOST_ENTRY_ATTR_ACTION;
            vhost_table_entry_attr[0].value.s32 = SAI_TABLE_VHOST_ENTRY_ACTION_TO_TUNNEL;
            vhost_table_entry_attr[1].id = SAI_TABLE_VHOST_ENTRY_ATTR_PRIORITY;
            vhost_table_entry_attr[1].value.u32 = 0; //TODO: either manage offset in here, or in mlnx_sai (preferably)
            vhost_table_entry_attr[2].id = SAI_TABLE_VHOST_ENTRY_ATTR_META_REG_KEY;
            vhost_table_entry_attr[2].value.u16 = vnet_bitmap; 
            vhost_table_entry_attr[3].id = SAI_TABLE_VHOST_ENTRY_ATTR_META_REG_MASK;
            vhost_table_entry_attr[3].value.u16 = vnet_bitmap;;
            vhost_table_entry_attr[6].id = SAI_TABLE_VHOST_ENTRY_ATTR_DST_IP;
            vhost_table_entry_attr[6].value.ipaddr.addr.ip4 = htonl(ip_prefix.getIp().getIp().ip_addr.ipv4_addr);
            vhost_table_entry_attr[6].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
            vhost_table_entry_attr[4].id = SAI_TABLE_VHOST_ENTRY_ATTR_UNDERLAY_DIP;
            vhost_table_entry_attr[4].value.ipaddr.addr.ip4 = htonl(underlay_dip);
            vhost_table_entry_attr[4].value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
            // vhost_table_entry_attr[5].id = SAI_TABLE_VHOST_ENTRY_ATTR_TUNNEL_ID;
            // vhost_table_entry_attr[5].value.oid = tunnel_id;
            sai_bmtor_api->create_table_vhost_entry(&vhost_table_entry, gSwitchId, 1, vhost_table_entry_attr);
        }
        //     if (alias == "lo")
        //     {
        //         addIp2MeRoute(ip_prefix);
        //         it = consumer.m_toSync.erase(it);
        //         continue;
        //     }

        //     Port port;
        //     if (!gPortsOrch->getPort(alias, port))
        //     {
        //         /* TODO: Resolve the dependency relationship and add ref_count to port */
        //         it++;
        //         continue;
        //     }

        //     auto it_intfs = m_syncdIntfses.find(alias);
        //     if (it_intfs == m_syncdIntfses.end())
        //     {
        //         if (addRouterIntfs(port))
        //         {
        //             IntfsEntry intfs_entry;
        //             intfs_entry.ref_count = 0;
        //             m_syncdIntfses[alias] = intfs_entry;
        //         }
        //         else
        //         {
        //             it++;
        //             continue;
        //         }
        //     }

        //     if (m_syncdIntfses[alias].ip_addresses.count(ip_prefix))
        //     {
        //         /* Duplicate entry */
        //         it = consumer.m_toSync.erase(it);
        //         continue;
        //     }

            /* NOTE: Overlap checking is required to handle ifconfig weird behavior.
             * When set IP address using ifconfig command it applies it in two stages.
             * On stage one it sets IP address with netmask /8. On stage two it
             * changes netmask to specified in command. As DB is async event to
             * add IP address with original netmask may come before event to
             * delete IP with netmask /8. To handle this we in case of overlap
             * we should wait until entry with /8 netmask will be removed.
             * Time frame between those event is quite small.*/
        //     bool overlaps = false;
        //     for (const auto &prefixIt: m_syncdIntfses[alias].ip_addresses)
        //     {
        //         if (prefixIt.isAddressInSubnet(ip_prefix.getIp()) ||
        //                 ip_prefix.isAddressInSubnet(prefixIt.getIp()))
        //         {
        //             overlaps = true;
        //             SWSS_LOG_NOTICE("Router interface %s IP %s overlaps with %s.", port.m_alias.c_str(),
        //                     prefixIt.to_string().c_str(), ip_prefix.to_string().c_str());
        //             break;
        //         }
        //     }

        //     if (overlaps)
        //     {
        //         /* Overlap of IP address network */
        //         ++it;
        //         continue;
        //     }

        //     addSubnetRoute(port, ip_prefix);
        //     addIp2MeRoute(ip_prefix);

        //     m_syncdIntfses[alias].ip_addresses.insert(ip_prefix);
        //     it = consumer.m_toSync.erase(it);
        // }
        // else if (op == DEL_COMMAND)
        // {
        //     if (alias == "lo")
        //     {
        //         removeIp2MeRoute(ip_prefix);
        //         it = consumer.m_toSync.erase(it);
        //         continue;
        //     }

        //     Port port;
        //     /* Cannot locate interface */
        //     if (!gPortsOrch->getPort(alias, port))
        //     {
        //         it = consumer.m_toSync.erase(it);
        //         continue;
        //     }

        //     if (m_syncdIntfses.find(alias) != m_syncdIntfses.end())
        //     {
        //         if (m_syncdIntfses[alias].ip_addresses.count(ip_prefix))
        //         {
        //             removeSubnetRoute(port, ip_prefix);
        //             removeIp2MeRoute(ip_prefix);

        //             m_syncdIntfses[alias].ip_addresses.erase(ip_prefix);
        //         }

        //         /* Remove router interface that no IP addresses are associated with */
        //         if (m_syncdIntfses[alias].ip_addresses.size() == 0)
        //         {
        //             if (removeRouterIntfs(port))
        //             {
        //                 m_syncdIntfses.erase(alias);
        //                 it = consumer.m_toSync.erase(it);
        //             }
        //             else
        //                 it++;
        //         }
        //         else
        //         {
        //             it = consumer.m_toSync.erase(it);
        //         }
        //     }
        //     else
        //         /* Cannot locate the interface */
        //         it = consumer.m_toSync.erase(it);
        // }
    }
}

// bool VnetRouteTunnelOrch::addRouterIntfs(Port &port)
// {
//     SWSS_LOG_ENTER();

//     /* Return true if the router interface exists */
//     if (port.m_rif_id)
//     {
//         SWSS_LOG_WARN("Router interface already exists on %s",
//                       port.m_alias.c_str());
//         return true;
//     }

//     /* Create router interface if the router interface doesn't exist */
//     sai_attribute_t attr;
//     vector<sai_attribute_t> attrs;

//     attr.id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
//     attr.value.oid = gVirtualRouterId;
//     attrs.push_back(attr);

//     attr.id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
//     memcpy(attr.value.mac, gMacAddress.getMac(), sizeof(sai_mac_t));
//     attrs.push_back(attr);

//     attr.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
//     switch(port.m_type)
//     {
//         case Port::PHY:
//         case Port::LAG:
//             attr.value.s32 = SAI_ROUTER_INTERFACE_TYPE_PORT;
//             break;
//         case Port::VLAN:
//             attr.value.s32 = SAI_ROUTER_INTERFACE_TYPE_VLAN;
//             break;
//         default:
//             SWSS_LOG_ERROR("Unsupported port type: %d", port.m_type);
//             break;
//     }
//     attrs.push_back(attr);

//     switch(port.m_type)
//     {
//         case Port::PHY:
//             attr.id = SAI_ROUTER_INTERFACE_ATTR_PORT_ID;
//             attr.value.oid = port.m_port_id;
//             break;
//         case Port::LAG:
//             attr.id = SAI_ROUTER_INTERFACE_ATTR_PORT_ID;
//             attr.value.oid = port.m_lag_id;
//             break;
//         case Port::VLAN:
//             attr.id = SAI_ROUTER_INTERFACE_ATTR_VLAN_ID;
//             attr.value.oid = port.m_vlan_info.vlan_oid;
//             break;
//         default:
//             SWSS_LOG_ERROR("Unsupported port type: %d", port.m_type);
//             break;
//     }
//     attrs.push_back(attr);

//     attr.id = SAI_ROUTER_INTERFACE_ATTR_MTU;
//     attr.value.u32 = port.m_mtu;
//     attrs.push_back(attr);

//     sai_status_t status = sai_router_intfs_api->create_router_interface(&port.m_rif_id, gSwitchId, (uint32_t)attrs.size(), attrs.data());
//     if (status != SAI_STATUS_SUCCESS)
//     {
//         SWSS_LOG_ERROR("Failed to create router interface for port %s, rv:%d", port.m_alias.c_str(), status);
//         throw runtime_error("Failed to create router interface.");
//     }

//     gPortsOrch->setPort(port.m_alias, port);

//     SWSS_LOG_NOTICE("Create router interface for port %s mtu %u", port.m_alias.c_str(), port.m_mtu);

//     return true;
// }

// bool VnetRouteTunnelOrch::removeRouterIntfs(Port &port)
// {
//     SWSS_LOG_ENTER();

//     if (m_syncdIntfses[port.m_alias].ref_count > 0)
//     {
//         SWSS_LOG_NOTICE("Router interface is still referenced");
//         return false;
//     }

//     sai_status_t status = sai_router_intfs_api->remove_router_interface(port.m_rif_id);
//     if (status != SAI_STATUS_SUCCESS)
//     {
//         SWSS_LOG_ERROR("Failed to remove router interface for port %s, rv:%d", port.m_alias.c_str(), status);
//         throw runtime_error("Failed to remove router interface.");
//     }

//     port.m_rif_id = 0;
//     gPortsOrch->setPort(port.m_alias, port);

//     SWSS_LOG_NOTICE("Remove router interface for port %s", port.m_alias.c_str());

//     return true;
// }

// void VnetRouteTunnelOrch::addSubnetRoute(const Port &port, const IpPrefix &ip_prefix)
// {
//     sai_route_entry_t unicast_route_entry;
//     unicast_route_entry.switch_id = gSwitchId;
//     unicast_route_entry.vr_id = gVirtualRouterId;
//     copy(unicast_route_entry.destination, ip_prefix);
//     subnet(unicast_route_entry.destination, unicast_route_entry.destination);

//     sai_attribute_t attr;
//     vector<sai_attribute_t> attrs;

//     attr.id = SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION;
//     attr.value.s32 = SAI_PACKET_ACTION_FORWARD;
//     attrs.push_back(attr);

//     attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
//     attr.value.oid = port.m_rif_id;
//     attrs.push_back(attr);

//     sai_status_t status = sai_route_api->create_route_entry(&unicast_route_entry, (uint32_t)attrs.size(), attrs.data());
//     if (status != SAI_STATUS_SUCCESS)
//     {
//         SWSS_LOG_ERROR("Failed to create subnet route to %s from %s, rv:%d",
//                        ip_prefix.to_string().c_str(), port.m_alias.c_str(), status);
//         throw runtime_error("Failed to create subnet route.");
//     }

//     SWSS_LOG_NOTICE("Create subnet route to %s from %s",
//                     ip_prefix.to_string().c_str(), port.m_alias.c_str());
//     increaseRouterIntfsRefCount(port.m_alias);
// }

// void VnetRouteTunnelOrch::removeSubnetRoute(const Port &port, const IpPrefix &ip_prefix)
// {
//     sai_route_entry_t unicast_route_entry;
//     unicast_route_entry.switch_id = gSwitchId;
//     unicast_route_entry.vr_id = gVirtualRouterId;
//     copy(unicast_route_entry.destination, ip_prefix);
//     subnet(unicast_route_entry.destination, unicast_route_entry.destination);

//     sai_status_t status = sai_route_api->remove_route_entry(&unicast_route_entry);
//     if (status != SAI_STATUS_SUCCESS)
//     {
//         SWSS_LOG_ERROR("Failed to remove subnet route to %s from %s, rv:%d",
//                        ip_prefix.to_string().c_str(), port.m_alias.c_str(), status);
//         throw runtime_error("Failed to remove subnet route.");
//     }

//     SWSS_LOG_NOTICE("Remove subnet route to %s from %s",
//                     ip_prefix.to_string().c_str(), port.m_alias.c_str());
//     decreaseRouterIntfsRefCount(port.m_alias);
// }

// void VnetRouteTunnelOrch::addIp2MeRoute(const IpPrefix &ip_prefix)
// {
//     sai_route_entry_t unicast_route_entry;
//     unicast_route_entry.switch_id = gSwitchId;
//     unicast_route_entry.vr_id = gVirtualRouterId;
//     copy(unicast_route_entry.destination, ip_prefix.getIp());

//     sai_attribute_t attr;
//     vector<sai_attribute_t> attrs;

//     attr.id = SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION;
//     attr.value.s32 = SAI_PACKET_ACTION_FORWARD;
//     attrs.push_back(attr);

//     Port cpu_port;
//     gPortsOrch->getCpuPort(cpu_port);

//     attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
//     attr.value.oid = cpu_port.m_port_id;
//     attrs.push_back(attr);

//     sai_status_t status = sai_route_api->create_route_entry(&unicast_route_entry, (uint32_t)attrs.size(), attrs.data());
//     if (status != SAI_STATUS_SUCCESS)
//     {
//         SWSS_LOG_ERROR("Failed to create IP2me route ip:%s, rv:%d", ip_prefix.getIp().to_string().c_str(), status);
//         throw runtime_error("Failed to create IP2me route.");
//     }

//     SWSS_LOG_NOTICE("Create IP2me route ip:%s", ip_prefix.getIp().to_string().c_str());
// }

// void VnetRouteTunnelOrch::removeIp2MeRoute(const IpPrefix &ip_prefix)
// {
//     sai_route_entry_t unicast_route_entry;
//     unicast_route_entry.switch_id = gSwitchId;
//     unicast_route_entry.vr_id = gVirtualRouterId;
//     copy(unicast_route_entry.destination, ip_prefix.getIp());

//     sai_status_t status = sai_route_api->remove_route_entry(&unicast_route_entry);
//     if (status != SAI_STATUS_SUCCESS)
//     {
//         SWSS_LOG_ERROR("Failed to remove IP2me route ip:%s, rv:%d", ip_prefix.getIp().to_string().c_str(), status);
//         throw runtime_error("Failed to remove IP2me route.");
//     }

//     SWSS_LOG_NOTICE("Remove packet action trap route ip:%s", ip_prefix.getIp().to_string().c_str());
// }
