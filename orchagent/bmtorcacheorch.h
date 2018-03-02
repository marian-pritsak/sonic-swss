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
private:
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
    sai_status_t create_tunnel();
    sai_object_id_t sai_get_port_id_by_alias(std::string alias);
    sai_ip4_t gVtepIp;
    uint16_t gVID;
    uint32_t gVNI;
    uint16_t gDPDKVlan;
    uint16_t gVnetBitmap;
    map<std::string, sai_object_id_t> vhost_entries;
    bool getVhostEntry(std::string key, sai_object_id_t &entry_id);
    void setVhostEntry(std::string key, sai_object_id_t entry_id);
};

#endif /* SWSS_BMTOR_CACHE_ORCH_H */