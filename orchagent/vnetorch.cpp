#include <cassert>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <exception>

#include <sairedis.h>

#include "sai.h"
#include "saiextensions.h"
#include "macaddress.h"
#include "orch.h"
#include "portsorch.h"
#include "request_parser.h"
#include "vnetorch.h"
#include "vxlanorch.h"
#include "swssnet.h"
#include "intfsorch.h"
#include "neighorch.h"
#include "crmorch.h"

extern sai_virtual_router_api_t* sai_virtual_router_api;
extern sai_route_api_t* sai_route_api;
extern sai_port_api_t* sai_port_api;
extern sai_bridge_api_t* sai_bridge_api;
extern sai_router_interface_api_t* sai_router_intfs_api;
extern sai_fdb_api_t* sai_fdb_api;
extern sai_neighbor_api_t* sai_neighbor_api;
extern sai_next_hop_api_t* sai_next_hop_api;
extern sai_bmtor_api_t* sai_bmtor_api;
extern sai_switch_api_t* sai_switch_api;
extern sai_acl_api_t *sai_acl_api;
extern sai_vlan_api_t *sai_vlan_api;
extern PortsOrch *gPortsOrch;
extern IntfsOrch *gIntfsOrch;
extern NeighOrch *gNeighOrch;
extern CrmOrch *gCrmOrch;
extern MacAddress gVxlanMacAddress;

/*
 * VRF Modeling and VNetVrf class definitions
 */
std::vector<VR_TYPE> vr_cntxt;

VNetVrfObject::VNetVrfObject(const std::string& vnet, const VNetInfo& vnetInfo,
                             vector<sai_attribute_t>& attrs) : VNetObject(vnetInfo)
{
    vnet_name_ = vnet;
    createObj(attrs);
}

sai_object_id_t VNetVrfObject::getVRidIngress() const
{
    if (vr_ids_.find(VR_TYPE::ING_VR_VALID) != vr_ids_.end())
    {
        return vr_ids_.at(VR_TYPE::ING_VR_VALID);
    }
    return SAI_NULL_OBJECT_ID;
}

sai_object_id_t VNetVrfObject::getVRidEgress() const
{
    if (vr_ids_.find(VR_TYPE::EGR_VR_VALID) != vr_ids_.end())
    {
        return vr_ids_.at(VR_TYPE::EGR_VR_VALID);
    }
    return SAI_NULL_OBJECT_ID;
}

set<sai_object_id_t> VNetVrfObject::getVRids() const
{
    set<sai_object_id_t> ids;

    for_each (vr_ids_.begin(), vr_ids_.end(), [&](std::pair<VR_TYPE, sai_object_id_t> element)
    {
        ids.insert(element.second);
    });

    return ids;
}

bool VNetVrfObject::createObj(vector<sai_attribute_t>& attrs)
{
    sai_object_id_t switch_id = getSwitchId();

    auto l_fn = [&] (sai_object_id_t& router_id) {

        sai_status_t status = sai_virtual_router_api->create_virtual_router(&router_id,
                                                                            switch_id,
                                                                            static_cast<uint32_t>(attrs.size()),
                                                                            attrs.data());
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to create virtual router name: %s, rv: %d",
                           vnet_name_.c_str(), status);
            throw std::runtime_error("Failed to create VR object");
        }
        return true;
    };

    /*
     * Create ingress and egress VRF based on VR_VALID
     */

    for (auto vr_type : vr_cntxt)
    {
        sai_object_id_t router_id;
        if (vr_type != VR_TYPE::VR_INVALID && l_fn(router_id))
        {
            SWSS_LOG_DEBUG("VNET vr_type %d router id %lx  ", static_cast<int>(vr_type), router_id);
            vr_ids_.insert(std::pair<VR_TYPE, sai_object_id_t>(vr_type, router_id));
        }
    }

    SWSS_LOG_INFO("VNET '%s' router object created ", vnet_name_.c_str());
    return true;
}

bool VNetVrfObject::updateObj(vector<sai_attribute_t>& attrs)
{
    set<sai_object_id_t> vr_ent = getVRids();

    for (const auto& attr: attrs)
    {
        for (auto it : vr_ent)
        {
            sai_status_t status = sai_virtual_router_api->set_virtual_router_attribute(it, &attr);
            if (status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("Failed to update virtual router attribute. VNET name: %s, rv: %d",
                                vnet_name_.c_str(), status);
                return false;
            }
        }
    }

    SWSS_LOG_INFO("VNET '%s' was updated", vnet_name_.c_str());
    return true;
}

bool VNetVrfObject::hasRoute(IpPrefix& ipPrefix)
{
    if ((routes_.find(ipPrefix) != routes_.end()) || (tunnels_.find(ipPrefix) != tunnels_.end()))
    {
        return true;
    }

    return false;
}

bool VNetVrfObject::addRoute(IpPrefix& ipPrefix, tunnelEndpoint& endp)
{
    if (hasRoute(ipPrefix))
    {
        SWSS_LOG_INFO("VNET route '%s' exists", ipPrefix.to_string().c_str());
        return false;
    }

    tunnels_[ipPrefix] = endp;
    return true;
}

bool VNetVrfObject::addRoute(IpPrefix& ipPrefix, nextHop& nh)
{
    if (hasRoute(ipPrefix))
    {
        SWSS_LOG_INFO("VNET route '%s' exists", ipPrefix.to_string().c_str());
        return false;
    }

    routes_[ipPrefix] = nh;
    return true;
}

bool VNetVrfObject::removeRoute(IpPrefix& ipPrefix)
{
    if (!hasRoute(ipPrefix))
    {
        SWSS_LOG_INFO("VNET route '%s' does'nt exist", ipPrefix.to_string().c_str());
        return false;
    }
    /*
     * Remove nexthop tunnel object before removing route
     */

    if (tunnels_.find(ipPrefix) != tunnels_.end())
    {
        auto endp = tunnels_.at(ipPrefix);
        removeTunnelNextHop(endp);
        tunnels_.erase(ipPrefix);
    }
    else
    {
        routes_.erase(ipPrefix);
    }
    return true;
}

size_t VNetVrfObject::getRouteCount() const
{
    return (routes_.size() + tunnels_.size());
}

bool VNetVrfObject::getRouteNextHop(IpPrefix& ipPrefix, nextHop& nh)
{
    if (!hasRoute(ipPrefix))
    {
        SWSS_LOG_INFO("VNET route '%s' does'nt exist", ipPrefix.to_string().c_str());
        return false;
    }

    nh = routes_.at(ipPrefix);
    return true;
}

sai_object_id_t VNetVrfObject::getTunnelNextHop(tunnelEndpoint& endp)
{
    sai_object_id_t nh_id = SAI_NULL_OBJECT_ID;
    auto tun_name = getTunnelName();

    VxlanTunnelOrch* vxlan_orch = gDirectory.get<VxlanTunnelOrch*>();

    nh_id = vxlan_orch->createNextHopTunnel(tun_name, endp.ip, endp.mac, endp.vni);
    if (nh_id == SAI_NULL_OBJECT_ID)
    {
        throw std::runtime_error("NH Tunnel create failed for " + vnet_name_ + " ip " + endp.ip.to_string());
    }

    return nh_id;
}

bool VNetVrfObject::removeTunnelNextHop(tunnelEndpoint& endp)
{
    auto tun_name = getTunnelName();

    VxlanTunnelOrch* vxlan_orch = gDirectory.get<VxlanTunnelOrch*>();

    if (!vxlan_orch->removeNextHopTunnel(tun_name, endp.ip, endp.mac, endp.vni))
    {
        SWSS_LOG_ERROR("VNET %s Tunnel NextHop remove failed for '%s'",
                        vnet_name_.c_str(), endp.ip.to_string().c_str());
        return false;
    }

    return true;
}

VNetVrfObject::~VNetVrfObject()
{
    set<sai_object_id_t> vr_ent = getVRids();
    for (auto it : vr_ent)
    {
        sai_status_t status = sai_virtual_router_api->remove_virtual_router(it);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to remove virtual router name: %s, rv:%d",
                            vnet_name_.c_str(), status);
        }
    }

    SWSS_LOG_INFO("VNET '%s' deleted ", vnet_name_.c_str());
}

/*
 * Bitmap based VNET class definition
 */
std::bitset<VNET_BITMAP_SIZE> VNetBitmapObject::vnetBitmap_;
std::bitset<VNET_TUNNEL_SIZE> VNetBitmapObject::tunnelOffsets_;
map<string, uint32_t> VNetBitmapObject::vnetIds_;
map<uint32_t, VnetBridgeInfo> VNetBitmapObject::bridgeInfoMap_;
map<tuple<MacAddress, sai_object_id_t>, VnetNeighInfo> VNetBitmapObject::neighInfoMap_;

VNetBitmapObject::VNetBitmapObject(const std::string& vnet, const VNetInfo& vnetInfo,
                             vector<sai_attribute_t>& attrs) : VNetObject(vnetInfo)
{
    SWSS_LOG_ENTER();

    setVniInfo(vnetInfo.vni);

    vnet_id_ = getFreeBitmapId(vnet);
    vnet_name_ = vnet;
}

bool VNetBitmapObject::updateObj(vector<sai_attribute_t>&)
{
    SWSS_LOG_ENTER();

    return false;
}

uint32_t VNetBitmapObject::getFreeBitmapId(const string& vnet)
{
    SWSS_LOG_ENTER();

    for (uint32_t i = 0; i < vnetBitmap_.size(); i++)
    {
        uint32_t id = 1 << i;
        if (vnetBitmap_[i] == false)
        {
            vnetBitmap_[i] = true;
            vnetIds_.emplace(vnet, id);
            return id;
        }
    }

    return 0;
}

uint32_t VNetBitmapObject::getBitmapId(const string& vnet)
{
    SWSS_LOG_ENTER();

    if (vnetIds_.find(vnet) == vnetIds_.end())
    {
        return 0;
    }

    return vnetIds_[vnet];
}

void VNetBitmapObject::recycleBitmapId(const string& vnet)
{
    SWSS_LOG_ENTER();

    uint32_t id = getBitmapId(vnet);
    if (id)
    {
        vnetBitmap_ &= ~id;
        vnetIds_.erase(vnet);
    }
}

uint32_t VNetBitmapObject::getFreeTunnelRouteTableOffset()
{
    SWSS_LOG_ENTER();

    for (uint32_t i = 0; i < tunnelOffsets_.size(); i++)
    {
        if (tunnelOffsets_[i] == false)
        {
            tunnelOffsets_[i] = true;
            return i;
        }
    }

    return -1;
}

void VNetBitmapObject::recycleTunnelRouteTableOffset(uint32_t offset)
{
    SWSS_LOG_ENTER();

    tunnelOffsets_[offset] = false;
}

VnetBridgeInfo VNetBitmapObject::getBridgeInfoByVni(uint32_t vni, string tunnelName)
{
    SWSS_LOG_ENTER();

    if (bridgeInfoMap_.find(vni) != bridgeInfoMap_.end())
    {
        bridgeInfoMap_.at(vni).use_count++;

        return std::move(bridgeInfoMap_.at(vni));
    }

    sai_status_t status;
    VnetBridgeInfo info;
    sai_attribute_t attr;
    vector<sai_attribute_t> bridge_attrs;
    attr.id = SAI_BRIDGE_ATTR_TYPE;
    attr.value.s32 = SAI_BRIDGE_TYPE_1D;
    bridge_attrs.push_back(attr);

    status = sai_bridge_api->create_bridge(
            &info.bridge_id,
            gSwitchId,
            (uint32_t)bridge_attrs.size(),
            bridge_attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create bridge for vni %u", vni);
        throw std::runtime_error("vni creation failed");
    }

    vector<sai_attribute_t> rif_attrs;

    attr.id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
    attr.value.oid = gVirtualRouterId;
    rif_attrs.push_back(attr);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
    memcpy(attr.value.mac, gMacAddress.getMac(), sizeof(sai_mac_t));
    rif_attrs.push_back(attr);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
    attr.value.s32 = SAI_ROUTER_INTERFACE_TYPE_BRIDGE;
    rif_attrs.push_back(attr);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_BRIDGE_ID;
    attr.value.oid = info.bridge_id;
    rif_attrs.push_back(attr);

    status = sai_router_intfs_api->create_router_interface(
            &info.rif_id,
            gSwitchId,
            (uint32_t)rif_attrs.size(),
            rif_attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create rif for vni %u", vni);
        throw std::runtime_error("vni creation failed");
    }

    vector<sai_attribute_t> bpr_attrs;

    attr.id = SAI_BRIDGE_PORT_ATTR_TYPE;
    attr.value.s32 = SAI_BRIDGE_PORT_TYPE_1D_ROUTER;
    bpr_attrs.push_back(attr);

    attr.id = SAI_BRIDGE_PORT_ATTR_RIF_ID;
    attr.value.oid = info.rif_id;
    bpr_attrs.push_back(attr);

    attr.id = SAI_BRIDGE_PORT_ATTR_BRIDGE_ID;
    attr.value.oid = info.bridge_id;
    bpr_attrs.push_back(attr);

    attr.id = SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE;
    attr.value.s32 = SAI_BRIDGE_PORT_FDB_LEARNING_MODE_DISABLE;
    bpr_attrs.push_back(attr);

    status = sai_bridge_api->create_bridge_port(
            &info.bridge_port_rif_id,
            gSwitchId,
            (uint32_t)bpr_attrs.size(),
            bpr_attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create rif bridge port for vni %u", vni);
        throw std::runtime_error("vni creation failed");
    }

    vector<sai_attribute_t> bpt_attrs;
    auto* vxlan_orch = gDirectory.get<VxlanTunnelOrch*>();
    auto *tunnel = vxlan_orch->getVxlanTunnel(tunnelName);
    if (!tunnel->isActive())
    {
        tunnel->createTunnel(MAP_T::BRIDGE_TO_VNI, MAP_T::VNI_TO_BRIDGE);
    }

    attr.id = SAI_BRIDGE_PORT_ATTR_TYPE;
    attr.value.s32 = SAI_BRIDGE_PORT_TYPE_TUNNEL;
    bpt_attrs.push_back(attr);

    attr.id = SAI_BRIDGE_PORT_ATTR_BRIDGE_ID;
    attr.value.oid = info.bridge_id;
    bpt_attrs.push_back(attr);

    attr.id = SAI_BRIDGE_PORT_ATTR_ADMIN_STATE;
    attr.value.booldata = true;
    bpt_attrs.push_back(attr);

    attr.id = SAI_BRIDGE_PORT_ATTR_TUNNEL_ID;
    attr.value.oid = tunnel->getTunnelId();
    bpt_attrs.push_back(attr);

    attr.id = SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE;
    attr.value.s32 = SAI_BRIDGE_PORT_FDB_LEARNING_MODE_DISABLE;
    bpt_attrs.push_back(attr);

    status = sai_bridge_api->create_bridge_port(
            &info.bridge_port_tunnel_id,
            gSwitchId,
            (uint32_t)bpt_attrs.size(),
            bpt_attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create tunnel bridge port for vni %u", vni);
        throw std::runtime_error("vni creation failed");
    }

    // FIXME: Use "createVxlanTunnelMap()" for tunnel mapper creation
    auto tunnelEncapMapperEntry = tunnel->addEncapMapperEntry(info.bridge_id, vni);
    tunnel->insertMapperEntry(tunnelEncapMapperEntry, SAI_NULL_OBJECT_ID, vni);

    info.use_count = 1;
    bridgeInfoMap_.emplace(vni, info);

    return std::move(info);
}

bool VNetBitmapObject::clearBridgeInfoByVni(uint32_t vni, string tunnelName)
{
    if (bridgeInfoMap_.find(vni) == bridgeInfoMap_.end())
    {
        SWSS_LOG_ERROR("Bridge info doesn't exist for VNI %u", vni);
        return false;
    }

    auto& bridgeInfo = bridgeInfoMap_.at(vni);
    if (bridgeInfo.use_count > 1)
    {
        bridgeInfo.use_count--;
    }
    else
    {
        auto vxlan_orch = gDirectory.get<VxlanTunnelOrch*>();
        if (!vxlan_orch->removeVxlanTunnelMap(tunnelName, vni))
        {
            return false;
        }

        sai_status_t status;

        status = sai_bridge_api->remove_bridge_port(bridgeInfo.bridge_port_tunnel_id);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to remove tunnel bridge port for VNI %u, SAI rc: %d", vni, status);
            return false;
        }

        status = sai_bridge_api->remove_bridge_port(bridgeInfo.bridge_port_rif_id);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to remove RIF bridge port for VNI %u, SAI rc: %d", vni, status);
            return false;
        }

        status = sai_router_intfs_api->remove_router_interface(bridgeInfo.rif_id);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to remove RIF for VNI %u, SAI rc: %d",vni, status);
            return false;
        }

        status = sai_bridge_api->remove_bridge(bridgeInfo.bridge_id);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to remove bridge for VNI %u, SAI rc: %d", vni, status);
            return false;
        }

        bridgeInfoMap_.erase(vni);
    }

    return true;
}

bool VNetBitmapObject::clearNeighInfo(MacAddress mac, sai_object_id_t bridge)
{
    auto macBridge = make_tuple(mac, bridge);

    if (neighInfoMap_.find(macBridge) == neighInfoMap_.end())
    {
        SWSS_LOG_ERROR("VNET neighbor doesn't exist");
        return false;
    }

    if (neighInfoMap_.at(macBridge).use_count > 1)
    {
        neighInfoMap_.at(macBridge).use_count--;
    }
    else
    {
        sai_status_t status;

        status = sai_neighbor_api->remove_neighbor_entry(&neighInfoMap_.at(macBridge).neigh_entry);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to remove neighbor entry, SAI rc: %d", status);
            return false;
        }

        status = sai_fdb_api->remove_fdb_entry(&neighInfoMap_.at(macBridge).fdb_entry);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to remove FDB entry, SAI rc: %d", status);
            return false;
        }

        neighInfoMap_.erase(macBridge);
    }

    return true;
}

void VNetBitmapObject::setVniInfo(uint32_t vni)
{
    sai_attribute_t attr;
    vector<sai_attribute_t> vnet_attrs;
    auto info = getBridgeInfoByVni(getVni(), getTunnelName());

    attr.id = SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ACTION;
    attr.value.s32 = SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ACTION_SET_METADATA;
    vnet_attrs.push_back(attr);

    attr.id = SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ROUTER_INTERFACE_KEY;
    attr.value.oid = info.rif_id;
    vnet_attrs.push_back(attr);

    attr.id = SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_IN_RIF_METADATA;
    attr.value.u32 = vnet_id_;
    vnet_attrs.push_back(attr);

    sai_status_t status = sai_bmtor_api->create_table_bitmap_classification_entry(
            &vnetTableEntryId_,
            gSwitchId,
            (uint32_t)vnet_attrs.size(),
            vnet_attrs.data());

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create VNET table entry, SAI rc: %d", status);
        throw std::runtime_error("VNet interface creation failed");
    }
}

bool VNetBitmapObject::addIntf(const string& alias, const IpPrefix *prefix)
{
    SWSS_LOG_ENTER();

    sai_attribute_t attr;
    vector<sai_attribute_t> vnet_attrs;
    vector<sai_attribute_t> route_attrs;
    sai_status_t status;
    uint32_t peerBitmap = vnet_id_;

    if (prefix && !prefix->isV4())
    {
        return false;
    }

    for (const auto& vnet : getPeerList())
    {
        uint32_t id = getBitmapId(vnet);
        if (id == 0)
        {
            SWSS_LOG_WARN("Peer vnet %s not ready", vnet.c_str());
            return false;
        }
        peerBitmap |= id;
    }

    if (gIntfsOrch->getSyncdIntfses().find(alias) == gIntfsOrch->getSyncdIntfses().end())
    {
        if (!gIntfsOrch->setIntf(alias, gVirtualRouterId, nullptr))
        {
            return false;
        }

        sai_object_id_t vnetTableEntryId;

        attr.id = SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ACTION;
        attr.value.s32 = SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ACTION_SET_METADATA;
        vnet_attrs.push_back(attr);

        attr.id = SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_ROUTER_INTERFACE_KEY;
        attr.value.oid = gIntfsOrch->getRouterIntfsId(alias);
        vnet_attrs.push_back(attr);

        attr.id = SAI_TABLE_BITMAP_CLASSIFICATION_ENTRY_ATTR_IN_RIF_METADATA;
        attr.value.u32 = vnet_id_;
        vnet_attrs.push_back(attr);

        status = sai_bmtor_api->create_table_bitmap_classification_entry(
                &vnetTableEntryId,
                gSwitchId,
                (uint32_t)vnet_attrs.size(),
                vnet_attrs.data());

        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to create VNET table entry, SAI rc: %d", status);
            throw std::runtime_error("VNet interface creation failed");
        }
    }

    if (prefix)
    {
        sai_object_id_t tunnelRouteTableEntryId;
        sai_ip_prefix_t saiPrefix;
        copy(saiPrefix, *prefix);

        gIntfsOrch->addIp2MeRoute(gVirtualRouterId, *prefix);

        attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ACTION;
        attr.value.s32 = SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_LOCAL;
        route_attrs.push_back(attr);

        attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_PRIORITY;
        attr.value.u32 = getFreeTunnelRouteTableOffset();
        route_attrs.push_back(attr);

        attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_KEY;
        attr.value.u64 = 0;
        route_attrs.push_back(attr);

        attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_MASK;
        attr.value.u64 = ~peerBitmap;
        route_attrs.push_back(attr);

        attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_DST_IP_KEY;
        attr.value.ipprefix = saiPrefix;
        route_attrs.push_back(attr);

        attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ROUTER_INTERFACE;
        attr.value.oid = gIntfsOrch->getRouterIntfsId(alias);
        route_attrs.push_back(attr);

        status = sai_bmtor_api->create_table_bitmap_router_entry(
                &tunnelRouteTableEntryId,
                gSwitchId,
                (uint32_t)route_attrs.size(),
                route_attrs.data());

        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to create local VNET route entry, SAI rc: %d", status);
            throw std::runtime_error("VNet interface creation failed");
        }
    }

    return true;
}

uint32_t VNetBitmapObject::getFreeNeighbor(void)
{
    static set<uint32_t> neighbors;

    for (uint32_t i = 0; i < VNET_NEIGHBOR_MAX; i++)
    {
        if (neighbors.count(i) == 0)
        {
            neighbors.insert(i);
            return i;
        }
    }

    SWSS_LOG_ERROR("No neighbors left");
    throw std::runtime_error("VNet route creation failed");
}

bool VNetBitmapObject::addTunnelRoute(IpPrefix& ipPrefix, tunnelEndpoint& endp)
{
    SWSS_LOG_ENTER();

    sai_status_t status;
    sai_attribute_t attr;
    auto& peer_list = getPeerList();
    auto bInfo = getBridgeInfoByVni(endp.vni == 0 ? getVni() : endp.vni, getTunnelName());
    uint32_t peerBitmap = vnet_id_;
    MacAddress mac = endp.mac ? endp.mac : gVxlanMacAddress;
    TunnelRouteInfo tunnelRouteInfo;

    VNetOrch* vnet_orch = gDirectory.get<VNetOrch*>();
    for (auto peer : peer_list)
    {
        if (!vnet_orch->isVnetExists(peer))
        {
            SWSS_LOG_INFO("Peer VNET %s not yet created", peer.c_str());
            return false;
        }
        peerBitmap |= getBitmapId(peer);
    }

    auto macBridge = make_tuple(mac, bInfo.bridge_id);
    if (neighInfoMap_.find(macBridge) == neighInfoMap_.end())
    {
        VnetNeighInfo neighInfo;

        /* FDB entry to the tunnel */
        vector<sai_attribute_t> fdb_attrs;
        sai_ip_address_t underlayAddr;
        copy(underlayAddr, endp.ip);
        neighInfo.fdb_entry.switch_id = gSwitchId;
        mac.getMac(neighInfo.fdb_entry.mac_address);
        neighInfo.fdb_entry.bv_id = bInfo.bridge_id;

        attr.id = SAI_FDB_ENTRY_ATTR_TYPE;
        attr.value.s32 = SAI_FDB_ENTRY_TYPE_STATIC;
        fdb_attrs.push_back(attr);

        attr.id = SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID;
        attr.value.oid = bInfo.bridge_port_tunnel_id;
        fdb_attrs.push_back(attr);

        attr.id = SAI_FDB_ENTRY_ATTR_ENDPOINT_IP;
        attr.value.ipaddr = underlayAddr;
        fdb_attrs.push_back(attr);

        status = sai_fdb_api->create_fdb_entry(
                &neighInfo.fdb_entry,
                (uint32_t)fdb_attrs.size(),
                fdb_attrs.data());
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to create fdb entry for tunnel, SAI rc: %d", status);
            throw std::runtime_error("VNet route creation failed");
        }

        /* Fake neighbor */
        neighInfo.neigh_entry.switch_id = gSwitchId;
        neighInfo.neigh_entry.rif_id = bInfo.rif_id;
        neighInfo.neigh_entry.ip_address.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        neighInfo.neigh_entry.ip_address.addr.ip4 = htonl(getFreeNeighbor());
        
        vector<sai_attribute_t> n_attrs;
        attr.id = SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS;
        mac.getMac(attr.value.mac);
        n_attrs.push_back(attr);

        status = sai_neighbor_api->create_neighbor_entry(
                &neighInfo.neigh_entry,
                (uint32_t)n_attrs.size(),
                n_attrs.data());
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to create neighbor entry for tunnel, SAI rc: %d", status);
            throw std::runtime_error("VNet route creation failed");
        }
        
        neighInfo.use_count = 1;
        neighInfoMap_.emplace(macBridge, neighInfo);
    }
    else
    {
        neighInfoMap_.at(macBridge).use_count++;
    }

    /* Nexthop */
    vector<sai_attribute_t> nh_attrs;

    attr.id = SAI_NEXT_HOP_ATTR_TYPE;
    attr.value.s32 = SAI_NEXT_HOP_TYPE_IP;
    nh_attrs.push_back(attr);

    attr.id = SAI_NEXT_HOP_ATTR_IP;
    attr.value.ipaddr = neighInfoMap_.at(macBridge).neigh_entry.ip_address;
    nh_attrs.push_back(attr);

    attr.id = SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID;
    attr.value.oid = bInfo.rif_id;
    nh_attrs.push_back(attr);

    status = sai_next_hop_api->create_next_hop(
            &tunnelRouteInfo.nexthopId,
            gSwitchId,
            (uint32_t)nh_attrs.size(),
            nh_attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create nexthop for tunnel, SAI rc: %d", status);
        throw std::runtime_error("VNet route creation failed");
    }

    /* Tunnel route */
    vector<sai_attribute_t> tr_attrs;
    sai_ip_prefix_t pfx;
    copy(pfx, ipPrefix);

    attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ACTION;
    attr.value.s32 = SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_NEXTHOP;
    tr_attrs.push_back(attr);

    tunnelRouteInfo.offset = getFreeTunnelRouteTableOffset();
    attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_PRIORITY;
    attr.value.u32 = tunnelRouteInfo.offset;
    tr_attrs.push_back(attr);

    attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_KEY;
    attr.value.u64 = 0;
    tr_attrs.push_back(attr);

    attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_MASK;
    attr.value.u64 = ~peerBitmap;
    tr_attrs.push_back(attr);

    attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_DST_IP_KEY;
    attr.value.ipprefix = pfx;
    tr_attrs.push_back(attr);

    attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_NEXT_HOP;
    attr.value.oid = tunnelRouteInfo.nexthopId;
    tr_attrs.push_back(attr);

    status = sai_bmtor_api->create_table_bitmap_router_entry(
            &tunnelRouteInfo.tunnelRouteTableEntryId,
            gSwitchId,
            (uint32_t)tr_attrs.size(),
            tr_attrs.data());

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create local VNET route entry, SAI rc: %d", status);
        throw std::runtime_error("VNet route creation failed");
    }

    tunnelRouteInfo.vni = endp.vni == 0 ? getVni() : endp.vni;
    tunnelRouteInfo.mac = mac;
    tunnelRouteMap_.emplace(ipPrefix, tunnelRouteInfo);

    return true;
}

bool VNetBitmapObject::removeTunnelRoute(IpPrefix& ipPrefix)
{
    SWSS_LOG_ENTER();

    if (tunnelRouteMap_.find(ipPrefix) == tunnelRouteMap_.end())
    {
        SWSS_LOG_WARN("VNET tunnel route %s doesn't exist", ipPrefix.to_string().c_str());
        return false;
    }

    auto tunnelRouteInfo = tunnelRouteMap_.at(ipPrefix);

    if (bridgeInfoMap_.find(tunnelRouteInfo.vni) == bridgeInfoMap_.end())
    {
        SWSS_LOG_ERROR("VNET bridge doesn't exist for tunnel route %s", ipPrefix.to_string().c_str());
        throw std::runtime_error("VNET tunnel route removal failed");
    }

    auto bridgeInfo = bridgeInfoMap_.at(tunnelRouteInfo.vni);
    auto macBridge = make_tuple(tunnelRouteInfo.mac, bridgeInfo.bridge_id);

    if (neighInfoMap_.find(macBridge) == neighInfoMap_.end())
    {
        SWSS_LOG_ERROR("VNET neighbor doesn't exist for tunnel route %s", ipPrefix.to_string().c_str());
        throw std::runtime_error("VNET tunnel route removal failed");
    }

    sai_status_t status;

    status = sai_bmtor_api->remove_table_bitmap_router_entry(tunnelRouteInfo.tunnelRouteTableEntryId);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to remove VNET tunnel route entry, SAI rc: %d", status);
        throw std::runtime_error("VNET tunnel route removal failed");
    }

    status = sai_next_hop_api->remove_next_hop(tunnelRouteInfo.nexthopId);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to remove nexthop entry for VNET tunnel route, SAI rc: %d", status);
        throw std::runtime_error("VNET tunnel route removal failed");
    }

    if (!clearNeighInfo(tunnelRouteInfo.mac, bridgeInfo.bridge_id))
    {
        throw std::runtime_error("VNET tunnel route removal failed");
    }

    if (!clearBridgeInfoByVni(tunnelRouteInfo.vni, getTunnelName()))
    {
        throw std::runtime_error("VNET tunnel route removal failed");
    }

    recycleTunnelRouteTableOffset(tunnelRouteInfo.offset);

    tunnelRouteMap_.erase(ipPrefix);

    return true;
}

bool VNetBitmapObject::addRoute(IpPrefix& ipPrefix, nextHop& nh)
{
    SWSS_LOG_ENTER();

    sai_status_t status;
    sai_attribute_t attr;
    vector<sai_attribute_t> attrs;
    sai_ip_prefix_t pfx;
    sai_object_id_t nh_id = SAI_NULL_OBJECT_ID;
    uint32_t peerBitmap = vnet_id_;
    Port port;
    RouteInfo routeInfo;

    bool is_subnet = (!nh.ips.getSize()) ? true : false;

    if (is_subnet && (!gPortsOrch->getPort(nh.ifname, port) || (port.m_rif_id == SAI_NULL_OBJECT_ID)))
    {
        SWSS_LOG_WARN("Port/RIF %s doesn't exist", nh.ifname.c_str());
        return false;
    }

    for (const auto& vnet : getPeerList())
    {
        uint32_t id = getBitmapId(vnet);
        if (id == 0)
        {
            SWSS_LOG_WARN("Peer vnet %s not ready", vnet.c_str());
            return false;
        }
        peerBitmap |= id;
    }

    /* Local route */
    copy(pfx, ipPrefix);

    if (is_subnet)
    {
        attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ACTION;
        attr.value.s32 = SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_LOCAL;
        attrs.push_back(attr);

        attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ROUTER_INTERFACE;
        attr.value.oid = port.m_rif_id;
        attrs.push_back(attr);
    }
    else if (nh.ips.getSize() == 1)
    {
        IpAddress ip_address(nh.ips.to_string());
        if (gNeighOrch->hasNextHop(ip_address))
        {
            nh_id = gNeighOrch->getNextHopId(ip_address);
        }
        else
        {
            SWSS_LOG_INFO("Failed to get next hop %s for %s",
                          ip_address.to_string().c_str(), ipPrefix.to_string().c_str());
            return false;
        }

        attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_ACTION;
        attr.value.s32 = SAI_TABLE_BITMAP_ROUTER_ENTRY_ACTION_TO_NEXTHOP;
        attrs.push_back(attr);

        attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_NEXT_HOP;
        attr.value.oid = nh_id;
        attrs.push_back(attr);
    }
    else
    {
        /* FIXME - Handle ECMP routes */
        SWSS_LOG_WARN("VNET ECMP NHs not implemented for '%s'", ipPrefix.to_string().c_str());
        return true;
    }

    routeInfo.offset = getFreeTunnelRouteTableOffset();
    attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_PRIORITY;
    attr.value.u32 = routeInfo.offset;
    attrs.push_back(attr);

    attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_KEY;
    attr.value.u64 = 0;
    attrs.push_back(attr);

    attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_IN_RIF_METADATA_MASK;
    attr.value.u64 = ~peerBitmap;
    attrs.push_back(attr);

    attr.id = SAI_TABLE_BITMAP_ROUTER_ENTRY_ATTR_DST_IP_KEY;
    attr.value.ipprefix = pfx;
    attrs.push_back(attr);

    status = sai_bmtor_api->create_table_bitmap_router_entry(
            &routeInfo.routeTableEntryId,
            gSwitchId,
            (uint32_t)attrs.size(),
            attrs.data());

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create local VNET route entry, SAI rc: %d", status);
        throw std::runtime_error("VNet route creation failed");
    }

    routeMap_.emplace(ipPrefix, routeInfo);

    return true;
}

bool VNetBitmapObject::removeRoute(IpPrefix& ipPrefix)
{
    SWSS_LOG_ENTER();

    if (routeMap_.find(ipPrefix) == routeMap_.end())
    {
        SWSS_LOG_WARN("VNET route %s doesn't exist", ipPrefix.to_string().c_str());
        return false;
    }

    sai_status_t status = sai_bmtor_api->remove_table_bitmap_router_entry(routeMap_.at(ipPrefix).routeTableEntryId);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to remove VNET route entry, SAI rc: %d", status);
        throw std::runtime_error("VNET route removal failed");
    }

    recycleTunnelRouteTableOffset(routeMap_.at(ipPrefix).offset);

    routeMap_.erase(ipPrefix);

    return true;
}

VNetBitmapObject::~VNetBitmapObject()
{
    sai_status_t status;
    
    status = sai_bmtor_api->remove_table_bitmap_classification_entry(vnetTableEntryId_);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to remove VNET '%s' table entry, SAI rc: %d", getVnetName().c_str(), status);
        throw std::runtime_error("VNET removal failed");
    }
    
    if (!clearBridgeInfoByVni(getVni(), getTunnelName()))
    {
        throw std::runtime_error("VNET removal failed");
    }

    recycleBitmapId(getVnetName());

    SWSS_LOG_INFO("VNET '%s' deleted ", getVnetName().c_str());
}

/*
 * VNet Orch class definitions
 */

template <class T>
std::unique_ptr<T> VNetOrch::createObject(const string& vnet_name, const VNetInfo& vnet_info,
                                          vector<sai_attribute_t>& attrs)
{
    std::unique_ptr<T> vnet_obj(new T(vnet_name, vnet_info, attrs));
    return vnet_obj;
}

VNetOrch::VNetOrch(DBConnector *db, const std::string& tableName, VNET_EXEC op)
         : Orch2(db, tableName, request_)
{
    vnet_exec_ = op;

    if (op == VNET_EXEC::VNET_EXEC_VRF)
    {
        vr_cntxt = { VR_TYPE::ING_VR_VALID, VR_TYPE::EGR_VR_VALID };
    }
    else
    {
        // BRIDGE Handling
    }
}

bool VNetOrch::setIntf(const string& alias, const string name, const IpPrefix *prefix)
{
    SWSS_LOG_ENTER();

    SWSS_LOG_ERROR(">>>>>>>>>>>>>>>>>>>> setIntf");

    if (!isVnetExists(name))
    {
        SWSS_LOG_WARN("VNET %s doesn't exist", name.c_str());
        return false;
    }

    if (isVnetExecVrf())
    {
        auto *vnet_obj = getTypePtr<VNetVrfObject>(name);
        VNetApplianceOrch* appliance_orch = gDirectory.get<VNetApplianceOrch*>();
        string appliance = vnet_obj->getApplianceName();
        if (!appliance.empty() && !appliance_orch->exists(appliance))
        {
            SWSS_LOG_WARN("Appliance %s doesn't exist", appliance.c_str());
            return false;
        }

        Port port;
        if (!gPortsOrch->getPort(alias, port))
        {
            SWSS_LOG_ERROR("failed to get port\n");
            return false;
        }

        if (!appliance_orch->redirectPortToOverlay(appliance, port))
        {
            SWSS_LOG_WARN("Appliance %s doesn't exist", appliance.c_str());
            return false;
        }

        /* sai_object_id_t vrf_id = vnet_obj->getVRidIngress(); */


        return gIntfsOrch->setIntf(alias, gVirtualRouterId, prefix);
    }
    else
    {
        auto *vnet_obj = getTypePtr<VNetBitmapObject>(name);
        return vnet_obj->addIntf(alias, prefix);
    }

    return false;
}
bool VNetOrch::addOperation(const Request& request)
{
    SWSS_LOG_ENTER();

    sai_attribute_t attr;
    vector<sai_attribute_t> attrs;
    set<string> peer_list = {};
    bool peer = false, create = false;
    uint32_t vni=0;
    string tunnel, appliance;

    for (const auto& name: request.getAttrFieldNames())
    {
        if (name == "src_mac")
        {
            const auto& mac = request.getAttrMacAddress("src_mac");
            attr.id = SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS;
            memcpy(attr.value.mac, mac.getMac(), sizeof(sai_mac_t));
            attrs.push_back(attr);
        }
        else if (name == "peer_list")
        {
            peer_list  = request.getAttrSet("peer_list");
            peer = true;
        }
        else if (name == "vni")
        {
            vni  = static_cast<sai_uint32_t>(request.getAttrUint("vni"));
        }
        else if (name == "vxlan_tunnel")
        {
            tunnel = request.getAttrString("vxlan_tunnel");
        }
        else if (name == "appliance")
        {
            appliance = request.getAttrString("appliance");
        }
        else
        {
            SWSS_LOG_INFO("Unknown attribute: %s", name.c_str());
            continue;
        }
    }

    const std::string& vnet_name = request.getKeyString(0);
    SWSS_LOG_INFO("VNET '%s' add request", vnet_name.c_str());

    VNetApplianceOrch* appliance_orch = gDirectory.get<VNetApplianceOrch*>();

    if (!appliance.empty() && appliance_orch->switch_id(appliance) == SAI_NULL_OBJECT_ID)
    {
        SWSS_LOG_WARN("Appliance '%s' doesn't exist", appliance.c_str());
        return false;
    }

    try
    {
        VNetObject_T obj;
        auto it = vnet_table_.find(vnet_name);
        if (isVnetExecVrf())
        {
            VxlanTunnelOrch* vxlan_orch = gDirectory.get<VxlanTunnelOrch*>();

            if (!vxlan_orch->isTunnelExists(tunnel))
            {
                SWSS_LOG_WARN("Vxlan tunnel '%s' doesn't exist", tunnel.c_str());
                return false;
            }

            if (it == std::end(vnet_table_))
            {
                VNetInfo vnet_info = { tunnel, vni, peer_list, appliance };
                obj = createObject<VNetVrfObject>(vnet_name, vnet_info, attrs);
                create = true;
            }

            VNetVrfObject *vrf_obj = dynamic_cast<VNetVrfObject*>(obj.get());
            if (!appliance.empty())
            {
                auto switch_id = appliance_orch->switch_id(appliance);
                auto loopback_rif_id = appliance_orch->loopback_rif_id(appliance);
                auto virtual_router_id = appliance_orch->virtual_router_id(appliance);
                auto *tunnelObj = vxlan_orch->getVxlanTunnel(tunnel);
                if (!tunnelObj->setSwitch(switch_id, loopback_rif_id, virtual_router_id))
                {
                    SWSS_LOG_WARN("Failed to set tunnel %s switch id 0x%lx", tunnel.c_str(), switch_id);
                    return false;
                }

                if (!appliance_orch->addVlan(appliance, (sai_vlan_id_t)vni, vrf_obj->getVRidIngress(), vrf_obj->getVRidEgress()))
                {
                    SWSS_LOG_WARN("Failed to add vlan");
                    return false;
                }

                if (!appliance_orch->redirectIpToUnderlay(appliance, tunnelObj->getTunnelIp(), vni))
                {
                    SWSS_LOG_WARN("failed to redirect to underlay");
                    return false;
                }
            }

            if (!vxlan_orch->createVxlanTunnelMap(tunnel, TUNNEL_MAP_T_VIRTUAL_ROUTER, vni,
                                                  vrf_obj->getEncapMapId(), vrf_obj->getDecapMapId()))
            {
                SWSS_LOG_ERROR("VNET '%s', tunnel '%s', map create failed",
                                vnet_name.c_str(), tunnel.c_str());
            }

            SWSS_LOG_INFO("VNET '%s' was added ", vnet_name.c_str());
        }
        else
        {
            VxlanTunnelOrch* vxlan_orch = gDirectory.get<VxlanTunnelOrch*>();

            if (!vxlan_orch->isTunnelExists(tunnel))
            {
                SWSS_LOG_WARN("Vxlan tunnel '%s' doesn't exist", tunnel.c_str());
                return false;
            }

            if (it == std::end(vnet_table_))
            {
                VNetInfo vnet_info = { tunnel, vni, peer_list, appliance };
                obj = createObject<VNetBitmapObject>(vnet_name, vnet_info, attrs);
                create = true;
            }
        }

        if (create)
        {
            vnet_table_[vnet_name] = std::move(obj);
        }
        else if (peer)
        {
            it->second->setPeerList(peer_list);
        }
        else if (!attrs.empty())
        {
            if(!it->second->updateObj(attrs))
            {
                return true;
            }
        }

    }
    catch(std::runtime_error& _)
    {
        SWSS_LOG_ERROR("VNET add operation error for %s: error %s ", vnet_name.c_str(), _.what());
        return false;
    }

    SWSS_LOG_INFO("VNET '%s' added/updated ", vnet_name.c_str());
    return true;
}

bool VNetOrch::delOperation(const Request& request)
{
    SWSS_LOG_ENTER();

    const std::string& vnet_name = request.getKeyString(0);

    if (vnet_table_.find(vnet_name) == std::end(vnet_table_))
    {
        SWSS_LOG_WARN("VNET '%s' doesn't exist", vnet_name.c_str());
        return true;
    }

    SWSS_LOG_INFO("VNET '%s' del request", vnet_name.c_str());

    try
    {
        auto it = vnet_table_.find(vnet_name);
        if (isVnetExecVrf())
        {
            VxlanTunnelOrch* vxlan_orch = gDirectory.get<VxlanTunnelOrch*>();
            VNetVrfObject *vrf_obj = dynamic_cast<VNetVrfObject*>(it->second.get());

            if (vrf_obj->getRouteCount())
            {
                SWSS_LOG_ERROR("VNET '%s': Routes are still present", vnet_name.c_str());
                return false;
            }

            if (!vxlan_orch->removeVxlanTunnelMap(vrf_obj->getTunnelName(), vrf_obj->getVni()))
            {
                SWSS_LOG_ERROR("VNET '%s' map delete failed", vnet_name.c_str());
                return false;
            }
        }
        else
        {
            auto vnet_obj = dynamic_cast<VNetBitmapObject*>(it->second.get());

            if (vnet_obj->getRouteCount())
            {
                SWSS_LOG_ERROR("VNET '%s': Routes are still present", vnet_name.c_str());
                return false;
            }
        }
    }
    catch(std::runtime_error& _)
    {
        SWSS_LOG_ERROR("VNET del operation error for %s: error %s ", vnet_name.c_str(), _.what());
        return false;
    }

    vnet_table_.erase(vnet_name);

    return true;
}

/*
 * Vnet Route Handling
 */

static bool del_route(sai_object_id_t vr_id, sai_object_id_t switch_id, sai_ip_prefix_t& ip_pfx)
{
    sai_route_entry_t route_entry;
    route_entry.vr_id = vr_id;
    route_entry.switch_id = switch_id;
    route_entry.destination = ip_pfx;

    sai_status_t status = sai_route_api->remove_route_entry(&route_entry);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("SAI Failed to remove route");
        return false;
    }

    if (route_entry.destination.addr_family == SAI_IP_ADDR_FAMILY_IPV4)
    {
        gCrmOrch->decCrmResUsedCounter(CrmResourceType::CRM_IPV4_ROUTE);
    }
    else
    {
        gCrmOrch->decCrmResUsedCounter(CrmResourceType::CRM_IPV6_ROUTE);
    }

    return true;
}

static bool add_route(sai_object_id_t vr_id, sai_object_id_t switch_id, sai_ip_prefix_t& ip_pfx, sai_object_id_t nh_id)
{
    sai_route_entry_t route_entry;
    route_entry.vr_id = vr_id;
    route_entry.switch_id = switch_id;
    route_entry.destination = ip_pfx;

    sai_attribute_t route_attr;

    route_attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
    route_attr.value.oid = nh_id;

    sai_status_t status = sai_route_api->create_route_entry(&route_entry, 1, &route_attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("SAI failed to create route");
        return false;
    }

    if (route_entry.destination.addr_family == SAI_IP_ADDR_FAMILY_IPV4)
    {
        gCrmOrch->incCrmResUsedCounter(CrmResourceType::CRM_IPV4_ROUTE);
    }
    else
    {
        gCrmOrch->incCrmResUsedCounter(CrmResourceType::CRM_IPV6_ROUTE);
    }

    return true;
}

VNetRouteOrch::VNetRouteOrch(DBConnector *db, vector<string> &tableNames, VNetOrch *vnetOrch)
                                  : Orch2(db, tableNames, request_), vnet_orch_(vnetOrch)
{
    SWSS_LOG_ENTER();

    handler_map_.insert(handler_pair(APP_VNET_RT_TABLE_NAME, &VNetRouteOrch::handleRoutes));
    handler_map_.insert(handler_pair(APP_VNET_RT_TUNNEL_TABLE_NAME, &VNetRouteOrch::handleTunnel));
}

template<>
bool VNetRouteOrch::doRouteTask<VNetVrfObject>(const string& vnet, IpPrefix& ipPrefix,
                                               tunnelEndpoint& endp, string& op)
{
    SWSS_LOG_ENTER();

    if (!vnet_orch_->isVnetExists(vnet))
    {
        SWSS_LOG_WARN("VNET %s doesn't exist", vnet.c_str());
        return false;
    }

    set<sai_object_id_t> vr_set;
    auto& peer_list = vnet_orch_->getPeerList(vnet);

    auto l_fn = [&] (const string& vnet) {
        auto *vnet_obj = vnet_orch_->getTypePtr<VNetVrfObject>(vnet);
        sai_object_id_t vr_id = vnet_obj->getVRidIngress();
        vr_set.insert(vr_id);
    };

    l_fn(vnet);
    for (auto peer : peer_list)
    {
        if (!vnet_orch_->isVnetExists(peer))
        {
            SWSS_LOG_INFO("Peer VNET %s not yet created", peer.c_str());
            return false;
        }
        l_fn(peer);
    }

    auto *vrf_obj = vnet_orch_->getTypePtr<VNetVrfObject>(vnet);
    sai_ip_prefix_t pfx;
    sai_object_id_t switch_id = vrf_obj->getSwitchId();
    copy(pfx, ipPrefix);
    sai_object_id_t nh_id = (op == SET_COMMAND)?vrf_obj->getTunnelNextHop(endp):SAI_NULL_OBJECT_ID;

    for (auto vr_id : vr_set)
    {
        if (op == SET_COMMAND && !add_route(vr_id, switch_id, pfx, nh_id))
        {
            SWSS_LOG_ERROR("Route add failed for %s, vr_id '0x%lx", ipPrefix.to_string().c_str(), vr_id);
            return false;
        }
        else if (op == DEL_COMMAND && !del_route(vr_id, switch_id, pfx))
        {
            SWSS_LOG_ERROR("Route del failed for %s, vr_id '0x%lx", ipPrefix.to_string().c_str(), vr_id);
            return false;
        }
    }

    if (op == SET_COMMAND)
    {
        vrf_obj->addRoute(ipPrefix, endp);
    }
    else
    {
        vrf_obj->removeRoute(ipPrefix);
    }

    return true;
}

template<>
bool VNetRouteOrch::doRouteTask<VNetVrfObject>(const string& vnet, IpPrefix& ipPrefix,
                                               nextHop& nh, string& op)
{
    SWSS_LOG_ENTER();

    if (!vnet_orch_->isVnetExists(vnet))
    {
        SWSS_LOG_WARN("VNET %s doesn't exist", vnet.c_str());
        return false;
    }

    auto *vrf_obj = vnet_orch_->getTypePtr<VNetVrfObject>(vnet);
    if (op == DEL_COMMAND && !vrf_obj->getRouteNextHop(ipPrefix, nh))
    {
        SWSS_LOG_WARN("VNET %s, Route %s get NH failed", vnet.c_str(), ipPrefix.to_string().c_str());
        return true;
    }

    bool is_subnet = (!nh.ips.getSize())?true:false;

    Port port;
    if (is_subnet && (!gPortsOrch->getPort(nh.ifname, port) || (port.m_rif_id == SAI_NULL_OBJECT_ID)))
    {
        SWSS_LOG_WARN("Port/RIF %s doesn't exist", nh.ifname.c_str());
        return false;
    }

    set<sai_object_id_t> vr_set;
    auto& peer_list = vnet_orch_->getPeerList(vnet);
    auto vr_id = vrf_obj->getVRidIngress();
    auto switch_id = vrf_obj->getSwitchId();

    /*
     * If RIF doesn't belong to this VRF, and if it is a replicated subnet
     * route for the peering VRF, Only install in ingress VRF.
     */

    if (!is_subnet)
    {
        vr_set = vrf_obj->getVRids();
    }
    else if (vr_id == port.m_vr_id)
    {
        vr_set.insert(vrf_obj->getVRidEgress());
    }
    else
    {
        vr_set.insert(vr_id);
    }

    auto l_fn = [&] (const string& vnet) {
        auto *vnet_obj = vnet_orch_->getTypePtr<VNetVrfObject>(vnet);
        sai_object_id_t vr_id = vnet_obj->getVRidIngress();
        vr_set.insert(vr_id);
    };

    for (auto peer : peer_list)
    {
        if (!vnet_orch_->isVnetExists(peer))
        {
            SWSS_LOG_INFO("Peer VNET %s not yet created", peer.c_str());
            return false;
        }
        l_fn(peer);
    }

    sai_ip_prefix_t pfx;
    copy(pfx, ipPrefix);
    sai_object_id_t nh_id=SAI_NULL_OBJECT_ID;

    if (is_subnet)
    {
        nh_id = port.m_rif_id;
    }
    else if (nh.ips.getSize() == 1)
    {
        IpAddress ip_address(nh.ips.to_string());
        if (gNeighOrch->hasNextHop(ip_address))
        {
            nh_id = gNeighOrch->getNextHopId(ip_address);
        }
        else
        {
            SWSS_LOG_INFO("Failed to get next hop %s for %s",
                           ip_address.to_string().c_str(), ipPrefix.to_string().c_str());
            return false;
        }
    }
    else
    {
        // FIXME - Handle ECMP routes
        SWSS_LOG_WARN("VNET ECMP NHs not implemented for '%s'", ipPrefix.to_string().c_str());
        return true;
    }

    for (auto vr_id : vr_set)
    {
        if (op == SET_COMMAND && !add_route(vr_id, switch_id, pfx, nh_id))
        {
            SWSS_LOG_ERROR("Route add failed for %s", ipPrefix.to_string().c_str());
            break;
        }
        else if (op == DEL_COMMAND && !del_route(vr_id, switch_id, pfx))
        {
            SWSS_LOG_ERROR("Route del failed for %s", ipPrefix.to_string().c_str());
            break;
        }
    }

    if (op == SET_COMMAND)
    {
        vrf_obj->addRoute(ipPrefix, nh);
    }
    else
    {
        vrf_obj->removeRoute(ipPrefix);
    }

    return true;
}

template<>
bool VNetRouteOrch::doRouteTask<VNetBitmapObject>(const string& vnet, IpPrefix& ipPrefix, tunnelEndpoint& endp, string& op)
{
    SWSS_LOG_ENTER();

    if (!vnet_orch_->isVnetExists(vnet))
    {
        SWSS_LOG_WARN("VNET %s doesn't exist", vnet.c_str());
        return false;
    }

    auto *vnet_obj = vnet_orch_->getTypePtr<VNetBitmapObject>(vnet);

    if (op == SET_COMMAND)
    {
        return vnet_obj->addTunnelRoute(ipPrefix, endp);
    }
    else
    {
        return vnet_obj->removeTunnelRoute(ipPrefix);
    }

    return true;
}

template<>
bool VNetRouteOrch::doRouteTask<VNetBitmapObject>(const string& vnet, IpPrefix& ipPrefix, nextHop& nh, string& op)
{
    SWSS_LOG_ENTER();

    if (!vnet_orch_->isVnetExists(vnet))
    {
        SWSS_LOG_WARN("VNET %s doesn't exist", vnet.c_str());
        return false;
    }

    auto *vnet_obj = vnet_orch_->getTypePtr<VNetBitmapObject>(vnet);

    if (op == SET_COMMAND)
    {
        return vnet_obj->addRoute(ipPrefix, nh);
    }
    else
    {
        return vnet_obj->removeRoute(ipPrefix);
    }

    return true;
}

bool VNetRouteOrch::handleRoutes(const Request& request)
{
    SWSS_LOG_ENTER();

    IpAddresses ip_addresses;
    string ifname = "";

    for (const auto& name: request.getAttrFieldNames())
    {
        if (name == "ifname")
        {
            ifname = request.getAttrString(name);
        }
        else if (name == "nexthop")
        {
            auto ipstr = request.getAttrString(name);
            ip_addresses = IpAddresses(ipstr);
        }
        else
        {
            SWSS_LOG_INFO("Unknown attribute: %s", name.c_str());
            continue;
        }
    }

    const std::string& vnet_name = request.getKeyString(0);
    auto ip_pfx = request.getKeyIpPrefix(1);
    auto op = request.getOperation();
    nextHop nh = { ip_addresses, ifname };

    SWSS_LOG_INFO("VNET-RT '%s' op '%s' for ip %s", vnet_name.c_str(),
                   op.c_str(), ip_pfx.to_string().c_str());

    if (vnet_orch_->isVnetExecVrf())
    {
        return doRouteTask<VNetVrfObject>(vnet_name, ip_pfx, nh, op);
    }
    else
    {
        return doRouteTask<VNetBitmapObject>(vnet_name, ip_pfx, nh, op);
    }

    return true;
}

bool VNetRouteOrch::handleTunnel(const Request& request)
{
    SWSS_LOG_ENTER();

    IpAddress ip;
    MacAddress mac;
    uint32_t vni = 0;

    for (const auto& name: request.getAttrFieldNames())
    {
        if (name == "endpoint")
        {
            ip = request.getAttrIP(name);
        }
        else if (name == "vni")
        {
            vni = static_cast<uint32_t>(request.getAttrUint(name));
        }
        else if (name == "mac_address")
        {
            mac = request.getAttrMacAddress(name);
        }
        else
        {
            SWSS_LOG_INFO("Unknown attribute: %s", name.c_str());
            continue;
        }
    }

    const std::string& vnet_name = request.getKeyString(0);
    auto ip_pfx = request.getKeyIpPrefix(1);
    auto op = request.getOperation();

    SWSS_LOG_INFO("VNET-RT '%s' op '%s' for pfx %s", vnet_name.c_str(),
                   op.c_str(), ip_pfx.to_string().c_str());

    tunnelEndpoint endp = { ip, mac, vni };

    if (vnet_orch_->isVnetExecVrf())
    {
        return doRouteTask<VNetVrfObject>(vnet_name, ip_pfx, endp, op);
    }
    else
    {
        return doRouteTask<VNetBitmapObject>(vnet_name, ip_pfx, endp, op);
    }

    return true;
}

bool VNetRouteOrch::addOperation(const Request& request)
{
    SWSS_LOG_ENTER();

    try
    {
        auto& tn = request.getTableName();
        if (handler_map_.find(tn) == handler_map_.end())
        {
            SWSS_LOG_ERROR(" %s handler is not initialized", tn.c_str());
            return true;
        }

        return ((this->*(handler_map_[tn]))(request));
    }
    catch(std::runtime_error& _)
    {
        SWSS_LOG_ERROR("VNET add operation error %s ", _.what());
        return true;
    }

    return true;
}

bool VNetRouteOrch::delOperation(const Request& request)
{
    SWSS_LOG_ENTER();

    try
    {
        auto& tn = request.getTableName();
        if (handler_map_.find(tn) == handler_map_.end())
        {
            SWSS_LOG_ERROR(" %s handler is not initialized", tn.c_str());
            return true;
        }

        return ((this->*(handler_map_[tn]))(request));
    }
    catch(std::runtime_error& _)
    {
        SWSS_LOG_ERROR("VNET del operation error %s ", _.what());
        return true;
    }

    return true;
}

/*
 * Vnet Appliance Handling
 */

VNetApplianceOrch::VNetApplianceOrch(DBConnector *db, vector<string> &tableNames)
                                  : Orch2(db, tableNames, request_)
{
    SWSS_LOG_ENTER();

}

bool VNetApplianceOrch::addVlan(string appliance, sai_vlan_id_t vlan_id, sai_object_id_t in_vrf_id, sai_object_id_t out_vrf_id)
{
    sai_attribute_t attr;
    vector<sai_attribute_t> attrs;
    sai_object_id_t vlan_oid, rif_oid;

    attr.id = SAI_VLAN_ATTR_VLAN_ID;
    attr.value.u16 = vlan_id;
    attrs.push_back(attr);

    sai_status_t status = sai_vlan_api->create_vlan(&vlan_oid,
                                                    switch_id(appliance),
                                                    (uint32_t)attrs.size(),
                                                    attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create a VLAN, rv:%d", status);
        throw std::runtime_error("Failed to create VLAN");
    }

    attrs.clear();

    attr.id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
    attr.value.oid = in_vrf_id;
    attrs.push_back(attr);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
    memcpy(attr.value.mac, gMacAddress.getMac(), sizeof(sai_mac_t));
    attrs.push_back(attr);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
    attr.value.s32 = SAI_ROUTER_INTERFACE_TYPE_VLAN;
    attrs.push_back(attr);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_VLAN_ID;
    attr.value.oid = vlan_oid;
    attrs.push_back(attr);

    status = sai_router_intfs_api->create_router_interface(&rif_oid,
                                                                        switch_id(appliance),
                                                                        (uint32_t)attrs.size(),
                                                                        attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create a VLAN, rv:%d", status);
        throw std::runtime_error("Failed to create VLAN");
    }

    attrs.clear();

    attr.id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
    attr.value.oid = out_vrf_id;
    attrs.push_back(attr);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
    memcpy(attr.value.mac, gMacAddress.getMac(), sizeof(sai_mac_t));
    attrs.push_back(attr);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
    attr.value.s32 = SAI_ROUTER_INTERFACE_TYPE_VLAN;
    attrs.push_back(attr);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_VLAN_ID;
    attr.value.oid = vlan_oid;
    attrs.push_back(attr);

    status = sai_router_intfs_api->create_router_interface(&rif_oid,
                                                                        switch_id(appliance),
                                                                        (uint32_t)attrs.size(),
                                                                        attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create a VLAN, rv:%d", status);
        throw std::runtime_error("Failed to create VLAN");
    }

    return true;
}

bool VNetApplianceOrch::addOperation(const Request& request)
{
    SWSS_LOG_ENTER();

    sai_attribute_t attr;
    vector<sai_attribute_t> attrs;
    string index;
    VNetApplianceInfo info;
    SWSS_LOG_ERROR("<><><><><><><><><><><><>BEGIN, rv:");

    for (const auto& name: request.getAttrFieldNames())
    {
        if (name == "overlay_interface")
        {
            info.overlay_intf = request.getAttrString(name);
        }
        else if (name == "underlay_interface")
        {
            info.underlay_intf = request.getAttrString(name);
        }
        else if (name == "index")
        {
            index = request.getAttrString(name);
        }
        else
        {
            SWSS_LOG_INFO("Unknown attribute: %s", name.c_str());
            continue;
        }
    }

    const std::string& appliance_name = request.getKeyString(0);

    attr.id = SAI_SWITCH_ATTR_INIT_SWITCH;
    attr.value.booldata = true;
    attrs.push_back(attr);

    char c_str[32];

    memcpy(c_str, index.c_str(), index.size() + 1);

    attr.id = SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO;
    attr.value.s8list.list = (int8_t *)c_str;
    attr.value.s8list.count = (uint32_t)index.size() + 1;
    attrs.push_back(attr);

    SWSS_LOG_ERROR("<><><><><><><><><><><><>BEFORE CREATE, rv:");
    sai_status_t status = sai_switch_api->create_switch(&info.switch_id,
            (uint32_t)attrs.size(),
            attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create a VNet Appliance switch, rv:%d", status);
        throw std::runtime_error("Failed to create VNet Appliance switch");
    }

    attrs.clear();

    /* Get the default virtual router ID */
    attr.id = SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID;

    status = sai_switch_api->get_switch_attribute(info.switch_id, 1, &attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Fail to get switch virtual router ID %d", status);
        exit(EXIT_FAILURE);
    }

    info.virtual_router_id = attr.value.oid;

    SWSS_LOG_NOTICE("Got default VR 0x%lx", attr.value.oid);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
    attr.value.oid = info.virtual_router_id;
    attrs.push_back(attr);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
    attr.value.s32 = SAI_ROUTER_INTERFACE_TYPE_LOOPBACK;
    attrs.push_back(attr);

    status = sai_router_intfs_api->create_router_interface(
            &info.loopback_rif_id,
            info.switch_id,
            (uint32_t)attrs.size(),
            attrs.data());

    SWSS_LOG_NOTICE("Created a switch");
    appliances_.emplace(appliance_name, info);

    return true;
}

bool VNetApplianceOrch::delOperation(const Request& request)
{
    SWSS_LOG_ENTER();

    /* const std::string& appliance_name = request.getKeyString(0); */

    return true;
}

bool VNetApplianceOrch::redirectPortToOverlay(string appliance, const Port& port)
{
    SWSS_LOG_ENTER();

    if (!initAcl())
    {
        SWSS_LOG_ERROR("ACL initialization failed");
    }

    if (appliances_.find(appliance) == appliances_.end())
    {
        SWSS_LOG_ERROR("No Such appliance %s\n", appliance.c_str());
        return false;
    }

    const auto& appliance_info = appliances_.at(appliance);
    Port overlay_port;
    if (!gPortsOrch->getPort(appliance_info.overlay_intf, overlay_port))
    {
        SWSS_LOG_ERROR("failed to get port\n");
        return false;
    }

    /* Assuming for now that it's a port RIF */
    sai_object_id_t rule_id = SAI_NULL_OBJECT_ID;
    sai_attribute_t attr;
    vector<sai_attribute_t> rule_attrs;
    attr.id = SAI_ACL_ENTRY_ATTR_TABLE_ID;
    attr.value.oid = overlay_acl_table_id_;
    rule_attrs.push_back(attr);

    attr.id = SAI_ACL_ENTRY_ATTR_PRIORITY;
    attr.value.u32 = 999;
    rule_attrs.push_back(attr);

    attr.id = SAI_ACL_ENTRY_ATTR_ADMIN_STATE;
    attr.value.booldata = true;
    rule_attrs.push_back(attr);

    attr.id = SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT;
    attr.value.aclfield.data.oid = port.m_port_id;
    rule_attrs.push_back(attr);

    attr.id = SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT;
    attr.value.aclaction.enable = true;
    attr.value.aclaction.parameter.oid = overlay_port.m_port_id;
    rule_attrs.push_back(attr);

    sai_status_t status = sai_acl_api->create_acl_entry(&rule_id,
                                           gSwitchId,
                                           (uint32_t)rule_attrs.size(),
                                           rule_attrs.data());
    if(status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("failed to create rule\n");
        return false;
    }

    attr.id = SAI_PORT_ATTR_INGRESS_ACL;
    attr.value.oid = overlay_acl_table_id_;

    status = sai_port_api->set_port_attribute(port.m_port_id, &attr);
    if(status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("failed to set ACL table to port");
        return false;
    }

    return true;
}

bool VNetApplianceOrch::redirectIpToUnderlay(string appliance, const IpAddress& ip, uint32_t vni)
{
    SWSS_LOG_ENTER();

    if (!initAcl())
    {
        SWSS_LOG_ERROR("ACL initialization failed");
    }

    if (appliances_.find(appliance) == appliances_.end())
    {
        SWSS_LOG_ERROR("No Such appliance %s\n", appliance.c_str());
        return false;
    }

    const auto& appliance_info = appliances_.at(appliance);
    Port underlay_port;
    if (!gPortsOrch->getPort(appliance_info.underlay_intf, underlay_port))
    {
        SWSS_LOG_ERROR("failed to get port\n");
        return false;
    }

    /* Assuming for now that it's a port RIF */
    sai_object_id_t rule_id = SAI_NULL_OBJECT_ID;
    sai_attribute_t attr;
    vector<sai_attribute_t> rule_attrs;
    attr.id = SAI_ACL_ENTRY_ATTR_TABLE_ID;
    attr.value.oid = underlay_acl_table_id_;
    rule_attrs.push_back(attr);

    attr.id = SAI_ACL_ENTRY_ATTR_PRIORITY;
    attr.value.u32 = 999;
    rule_attrs.push_back(attr);

    attr.id = SAI_ACL_ENTRY_ATTR_ADMIN_STATE;
    attr.value.booldata = true;
    rule_attrs.push_back(attr);

    sai_ip_address_t ip_addr;
    copy(ip_addr, ip);
    attr.id = SAI_ACL_ENTRY_ATTR_FIELD_DST_IP;
    attr.value.aclfield.data.ip4 = ip_addr.addr.ip4;
    attr.value.aclfield.mask.ip4 = 0xffffffff;
    rule_attrs.push_back(attr);

    attr.id = SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT;
    attr.value.aclfield.data.u16 = 4789;
    attr.value.aclfield.mask.u16 = 0xffff;
    rule_attrs.push_back(attr);

    attr.id = SAI_ACL_ENTRY_ATTR_FIELD_TUNNEL_VNI;
    attr.value.aclfield.data.u32 = vni;
    attr.value.aclfield.mask.u32 = 0xffffffff;
    rule_attrs.push_back(attr);

    attr.id = SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT;
    attr.value.aclaction.enable = true;
    attr.value.aclaction.parameter.oid = underlay_port.m_port_id;
    rule_attrs.push_back(attr);

    sai_status_t status = sai_acl_api->create_acl_entry(&rule_id,
                                           gSwitchId,
                                           (uint32_t)rule_attrs.size(),
                                           rule_attrs.data());
    if(status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("failed to create rule\n");
        return false;
    }

    return true;
}

bool VNetApplianceOrch::initAcl(void)
{
    SWSS_LOG_ENTER();

    if (overlay_acl_table_id_ != SAI_NULL_OBJECT_ID)
    {
        return true;
    }

    vector<sai_attribute_t> table_attrs;
    sai_attribute_t attr;

    vector<int32_t> bpoint_list = { SAI_ACL_BIND_POINT_TYPE_PORT, SAI_ACL_BIND_POINT_TYPE_LAG };
    attr.id = SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST;
    attr.value.s32list.count = static_cast<uint32_t>(bpoint_list.size());
    attr.value.s32list.list = bpoint_list.data();
    table_attrs.push_back(attr);

    attr.id = SAI_ACL_TABLE_ATTR_FIELD_IN_PORT;
    attr.value.booldata = true;
    table_attrs.push_back(attr);

    attr.id = SAI_ACL_TABLE_ATTR_ACL_STAGE;
    attr.value.s32 = SAI_ACL_STAGE_INGRESS;
    table_attrs.push_back(attr);

    attr.id = SAI_ACL_TABLE_ATTR_SIZE;
    attr.value.u32 = 64;
    table_attrs.push_back(attr);

    sai_status_t status = sai_acl_api->create_acl_table(&overlay_acl_table_id_,
                                           gSwitchId,
                                           (uint32_t)table_attrs.size(),
                                           table_attrs.data());
    if(status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create acl table: %d\n", status);
        return false;
    }

    auto port_map = gPortsOrch->getAllPorts();

    table_attrs.clear();

    attr.id = SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST;
    attr.value.s32list.count = static_cast<uint32_t>(bpoint_list.size());
    attr.value.s32list.list = bpoint_list.data();
    table_attrs.push_back(attr);

    attr.id = SAI_ACL_TABLE_ATTR_FIELD_DST_IP;
    attr.value.booldata = true;
    table_attrs.push_back(attr);

    attr.id = SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT;
    attr.value.booldata = true;
    table_attrs.push_back(attr);

    attr.id = SAI_ACL_TABLE_ATTR_FIELD_TUNNEL_VNI;
    attr.value.booldata = true;
    table_attrs.push_back(attr);

    attr.id = SAI_ACL_TABLE_ATTR_ACL_STAGE;
    attr.value.s32 = SAI_ACL_STAGE_INGRESS;
    table_attrs.push_back(attr);

    attr.id = SAI_ACL_TABLE_ATTR_SIZE;
    attr.value.u32 = 64;
    table_attrs.push_back(attr);

    status = sai_acl_api->create_acl_table(&underlay_acl_table_id_,
                                           gSwitchId,
                                           (uint32_t)table_attrs.size(),
                                           table_attrs.data());

    if(status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create acl table: %d\n", status);
        return false;
    }

    for (const auto& kv: port_map)
    {
        const Port& port = kv.second;
        attr.id = SAI_PORT_ATTR_INGRESS_ACL;
        attr.value.oid = underlay_acl_table_id_;

        if (port.m_type == Port::PHY) {
            status = sai_port_api->set_port_attribute(port.m_port_id, &attr);
            if(status != SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_ERROR("failed to set ACL table to port");
                return false;
            }
        }
    }

    return true;
}
