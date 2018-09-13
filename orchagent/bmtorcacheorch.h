#ifndef SWSS_BMTOR_CACHE_ORCH_H
#define SWSS_BMTOR_CACHE_ORCH_H

#include "orch.h"
#include "portsorch.h"

#include "ipaddresses.h"
#include "ipprefix.h"
#include "macaddress.h"

#include <map>
#include <set>
#include <memory>

#define NUM_OF_VNI 900
#define VHOST_TABLE_SIZE 8192
#define MAX_VNETS_NUM 12

// TODO: Move to VnetOrch?
class Vnet 
{
public:
    Vnet(uint16_t _bitmap_offset);
    /* void AddPeer(std::string peer); */
    set<std::string> peering_list;
    uint32_t vni;
    uint16_t bitmap_offset;
};

class BmToRCacheOrch : public Orch
{
public:
    BmToRCacheOrch(DBConnector *db, vector<string> tableNames);
    /* sai_object_id_t getDPDKPort(); */
    /* string getDPDKPortIF(); */
    sai_object_id_t GetTunnelID();
    sai_status_t CreateVhostEntry(sai_object_id_t *entry_id, IpAddress underlay_dip, IpAddress overlay_dip, uint32_t vni, uint16_t vnet_bitmap_offset, std::string vnet_name);
    sai_status_t RemoveTableVhost(sai_object_id_t entry_id);
    sai_status_t getBridgeMapEntryByVni(uint32_t vni, sai_object_id_t& bridgeId, sai_object_id_t& mapEntry);
private:
    void doVnetRouteTunnelTask(Consumer &consumer);
    void doVnetRouteTask(Consumer &consumer);
    void doVnetTask(Consumer &consumer);
    void doVnetIntfTask(Consumer &consumer);
    void doVxlanTunnelTask(Consumer &consumer);
    void doEncapTunnelTask(Consumer &consumer);
    void doTask(Consumer &consumer);
    uint16_t GetVnetBitmap(std::shared_ptr<Vnet> vnet);
    sai_object_id_t AddTablePeeringEntry(uint16_t vnet_bitmap, sai_object_id_t bm_port_oid);
    bool GetFreeVnetOffset(uint16_t &vnet_offset);
    sai_object_id_t gTunnelId;
    sai_object_id_t default1Qbridge;
    /* sai_object_id_t gDpdkBirdgePort; */
    sai_object_id_t default_vhost_table_entry;
    /* sai_object_id_t dpdk_port; */
    sai_object_id_t bm_port_oid;
    sai_object_id_t peering_entry;
    sai_status_t create_tunnel(IpAddress src_ip);
    sai_object_id_t sai_get_port_id_by_alias(std::string alias);
    sai_object_id_t sai_get_port_id_by_front_port(uint32_t hw_port);
    IpAddress gTunnelSrcIp;;
    /* uint16_t gVlansStart; */
    /* uint32_t gVni; */
    /* uint16_t gDPDKVlan; */
    /* uint16_t gVnetBitmap; */
    
    map<std::string, sai_object_id_t> vhost_entries;
    bool getVhostEntry(std::string key, sai_object_id_t &entry_id);
    void setVhostEntry(std::string key, sai_object_id_t entry_id);
    
    bool removeVhostEntry(sai_object_id_t entry_id);
    map<std::string, IpAddress> tunnel_ip_map;
    bool getTunnelIP(std::string key, IpAddress &IP);
    void setTunnelIP(std::string key, IpAddress IP);

    map<std::string, std::shared_ptr<Vnet>> vnet_map;
    bool getVnet(std::string key, std::shared_ptr<Vnet> &vnet);
    void setVnet(std::string key, std::shared_ptr<Vnet> vnet);

    /* map<std::string, sai_object_id_t> vnet_vlan_map; */
    /* bool getVnetVlan(std::string key, sai_object_id_t &Vlan); */
    /* void setVnetVlan(std::string key, sai_object_id_t Vlan); */

    /* void create_dpdk_bridge_port(); */
    /* sai_object_id_t create_vlan(uint16_t vid); */
    /* sai_object_id_t add_dpdk_vlan_member(sai_object_id_t vlan_oid); */
    /* uint16_t get_new_vlan(); */
    /* bool is_vlan_used(uint16_t vid); */
    uint32_t GetFreeOffset();
    void RemoveOffset(sai_object_id_t entry_id);
    std::map<sai_object_id_t, uint32_t> used_offsets;
    /* uint16_t get_vid_from_vlan(sai_object_id_t vlan_oid); */
    uint32_t gVhostTableSize;
    map<uint32_t, pair<sai_object_id_t, sai_object_id_t>> vniToBridgeMap;
    sai_object_id_t tunnel_encap_map;
};

#endif /* SWSS_BMTOR_CACHE_ORCH_H */
