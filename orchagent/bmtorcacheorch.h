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
    uint16_t GetVnetBitmap(uint32_t vni);
    sai_object_id_t GetTunnelID();
    sai_status_t CreateVhostEntry(sai_object_id_t *entry_id, IpAddress underlay_dip, IpAddress overlay_dip, uint32_t vni);
private:
    void InitDefaultEntries();
    void doVnetRouteTunnelTask(Consumer &consumer);
    void doVnetRouteTask(Consumer &consumer);
    void doVnetTask(Consumer &consumer);
    void doVnetIntfTask(Consumer &consumer);
    void doVxlanTunnelTask(Consumer &consumer);
    void doTask(Consumer &consumer);
    bool tunnel_created;
    sai_object_id_t gTunnelId;
    sai_object_id_t default1Qbridge;
    sai_object_id_t default_vhost_table_entry;
    sai_object_id_t dpdk_port;
    sai_object_id_t port_10_oid;
    sai_object_id_t peering_entry;
    sai_status_t create_tunnel(IpAddress src_ip, uint32_t vni);
    sai_object_id_t sai_get_port_id_by_alias(std::string alias);
    sai_object_id_t sai_get_port_id_by_front_port(uint32_t hw_port);
    IpAddress gTunnelSrcIp;;
    uint16_t gVID;
    // uint32_t gVNI;
    sai_object_id_t gBridgeId;// TODO remove
    uint16_t gDPDKVlan;
    uint16_t gVnetBitmap;
    map<std::string, sai_object_id_t> vhost_entries;
    map<std::string, IpAddress> tunnel_ip_map;
    bool getVhostEntry(std::string key, sai_object_id_t &entry_id);
    void setVhostEntry(std::string key, sai_object_id_t entry_id);
    bool getTunnelIP(std::string key, IpAddress &IP);
    void setTunnelIP(std::string key, IpAddress IP);
};

#endif /* SWSS_BMTOR_CACHE_ORCH_H */