#ifndef __VRFORCH_H
#define __VRFORCH_H

#include "request_parser.h"

extern sai_object_id_t gVirtualRouterId;
typedef std::unordered_map<std::string, sai_object_id_t> VRFTable;

const request_description_t request_description = {
    { REQ_T_STRING },
    {
        { "v4",            REQ_T_BOOL },
        { "v6",            REQ_T_BOOL },
        { "src_mac",       REQ_T_MAC_ADDRESS },
        { "ttl_action",    REQ_T_PACKET_ACTION },
        { "ip_opt_action", REQ_T_PACKET_ACTION },
        { "l3_mc_action",  REQ_T_PACKET_ACTION },
        { "vnet_name",     REQ_T_STRING },
        { "fall_through",  REQ_T_BOOL },
        { "peer_list",     REQ_T_SET },
    },
    { } // no mandatory attributes
};

class VRFRequest : public Request
{
public:
    VRFRequest() : Request(request_description, ':') { }
};

class VNetObject
{
public:
    VNetObject(string vr_name, sai_object_id_t ivr_id, sai_object_id_t evr_id, set<string>& list)
              :vrf_name(vr_name), i_vrf_id(ivr_id),e_vrf_id(evr_id)
    {
        peer_list = list;
    }

    sai_object_id_t getVRFidIngress() const
    {
        return i_vrf_id;
    }

    sai_object_id_t getVRFidEgress() const
    {
        return e_vrf_id;
    }

    string getVRFname() const
    {
        return vrf_name;
    }

private:
    string vrf_name;
    set<string> peer_list = {};
    sai_object_id_t i_vrf_id;
    sai_object_id_t e_vrf_id;
};

using VNetObject_T = std::unique_ptr<VNetObject>;
typedef std::unordered_map<std::string, VNetObject_T> VNetTable;
typedef std::unordered_map<std::string, std::string> VRFMapTable;

class VRFOrch : public Orch2
{
public:
    VRFOrch(DBConnector *db, const std::string& tableName) : Orch2(db, tableName, request_)
    {
    }

    bool isVRFexists(const std::string& name) const
    {
        return vrf_table_.find(name) != std::end(vrf_table_);
    }

    sai_object_id_t getVRFid(const std::string& name) const
    {
        if (vrf_table_.find(name) != std::end(vrf_table_))
        {
            return vrf_table_.at(name);
        }
        else
        {
            return gVirtualRouterId;
        }
    }

    bool isVnetexists(const std::string& name) const
    {
        return vnet_table_.find(name) != std::end(vnet_table_);
    }

    sai_object_id_t getVRFidIngress(const std::string& name) const
    {
        return vnet_table_.at(name)->getVRFidIngress();
    }

    sai_object_id_t getVRFidEgress(const std::string& name) const
    {
        return vnet_table_.at(name)->getVRFidEgress();
    }

    bool isMapexists(const std::string& name) const
    {
        return map_table_.find(name) != std::end(map_table_);
    }

    string getVnetName(const std::string& vrf) const
    {
        return map_table_.at(vrf);
    }

private:
    virtual bool addOperation(const Request& request);
    virtual bool delOperation(const Request& request);

    VRFTable vrf_table_;
    VNetTable vnet_table_;
    VRFMapTable map_table_; //VRF to Vnet Map
    VRFRequest request_;
};

#endif // __VRFORCH_H
