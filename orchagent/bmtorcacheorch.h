#ifndef SWSS_BMTOR_CACHE_ORCH_H
#define SWSS_BMTOR_CACHE_ORCH_H

#include "orch.h"
#include "portsorch.h"

#include "ipaddresses.h"
#include "ipprefix.h"
#include "macaddress.h"

#include <map>
#include <set>

extern sai_object_id_t gVirtualRouterId;
extern sai_object_id_t gUnderlayIfId;

class BmToRCacheOrch : public Orch
{
public:
    BmToRCacheOrch(DBConnector *db, vector<string> tableNames);
    sai_object_id_t getDPDKPort();
    string getDPDKPortIF();
    uint16_t GetVnetBitmap(uint32_t vni);
    sai_object_id_t GetTunnelID();
    sai_status_t CreateVhostEntry(sai_object_id_t *entry_id, IpAddress underlay_dip, IpAddress overlay_dip, uint32_t vni);
    sai_status_t RemoveTableVhost(sai_object_id_t entry_id);
private:
    void InitDefaultEntries();
    void doVnetRouteTunnelTask(Consumer &consumer);
    void doVnetRouteTask(Consumer &consumer);
    void doVnetTask(Consumer &consumer);
    void doVnetIntfTask(Consumer &consumer);
    void doVxlanTunnelTask(Consumer &consumer);
    void doTask(Consumer &consumer);
    sai_object_id_t gTunnelId;
    sai_object_id_t default1Qbridge;
    sai_object_id_t gDpdkBirdgePort;
    sai_object_id_t default_vhost_table_entry;
    sai_object_id_t dpdk_port;
    sai_object_id_t bm_port_oid;
    sai_object_id_t peering_entry;
    sai_status_t create_tunnel(IpAddress src_ip, uint32_t vni);
    sai_object_id_t sai_get_port_id_by_alias(std::string alias);
    sai_object_id_t sai_get_port_id_by_front_port(uint32_t hw_port);
    IpAddress gTunnelSrcIp;;
    uint16_t gVlansStart;
    // uint32_t gVNI;
    sai_object_id_t gBridgeId;// TODO remove
    uint16_t gDPDKVlan;
    uint16_t gVnetBitmap;
    map<std::string, sai_object_id_t> vhost_entries;
    map<std::string, IpAddress> tunnel_ip_map;
    map<std::string, sai_object_id_t> vnet_vlan_map;
    bool getVhostEntry(std::string key, sai_object_id_t &entry_id);
    void setVhostEntry(std::string key, sai_object_id_t entry_id);
    bool removeVhostEntry(sai_object_id_t entry_id);
    bool getTunnelIP(std::string key, IpAddress &IP);
    void setTunnelIP(std::string key, IpAddress IP);
    bool getVnetVlan(std::string key, sai_object_id_t &Vlan);
    void setVnetVlan(std::string key, sai_object_id_t Vlan);
    void create_dpdk_bridge_port();
    sai_object_id_t create_vlan(uint16_t vid);
    sai_object_id_t add_dpdk_vlan_member(sai_object_id_t vlan_oid);
    uint16_t get_new_vlan();
    bool is_vlan_used(uint16_t vid);
    uint32_t GetFreeOffset();
    void RemoveOffset(sai_object_id_t entry_id);
    std::map<sai_object_id_t, uint32_t> used_offsets;
    uint16_t get_vid_from_vlan(sai_object_id_t vlan_oid);
    uint32_t gVhostTableSize;
};

#endif /* SWSS_BMTOR_CACHE_ORCH_H */