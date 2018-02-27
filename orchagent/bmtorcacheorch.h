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
    sai_object_id_t sai_get_port_id_by_front_port(uint32_t hw_port);
    sai_object_id_t sai_get_port_id_by_alias(std::string alias)
    sai_ip4_t gVtepIp;
    uint16_t gVID;
    uint32_t gVNI;
};

#endif /* SWSS_BMTOR_CACHE_ORCH_H */