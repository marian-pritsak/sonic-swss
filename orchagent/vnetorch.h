#ifndef __VNETORCH_H
#define __VNETORCH_H

#include <vector>
#include <set>
#include <unordered_map>
#include <algorithm>

#include "request_parser.h"

extern sai_object_id_t gVirtualRouterId;

const request_description_t vnet_request_description = {
    { REQ_T_STRING },
    {
        { "src_mac",       REQ_T_MAC_ADDRESS },
        { "vxlan_tunnel",  REQ_T_STRING },
        { "vni",           REQ_T_UINT },
        { "peer_list",     REQ_T_SET },
    },
    { "vxlan_tunnel", "vni" } // mandatory attributes
};

enum class VR_TYPE
{
    ING_VR_VALID,
    EGR_VR_VALID,
    VR_INVALID
};

struct tunnelEndpoint
{
    IpAddress ip;
    MacAddress mac;
    uint32_t vni;
};

typedef map<VR_TYPE, sai_object_id_t> vrid_list_t;
extern std::vector<VR_TYPE> vr_cntxt;

class VNetRequest : public Request
{
public:
    VNetRequest() : Request(vnet_request_description, ':') { }
};

class VNetObject
{
public:
    VNetObject(string& tunName, set<string>& peer) : tunnel_(tunName), peer_list_(peer) { }

    virtual bool updateObj(vector<sai_attribute_t>&) = 0;

    virtual bool addIntf(Port& port, IpPrefix *prefix)
    {
        return false;
    }

    virtual bool addRoute(IpPrefix& ipPrefix, string& ifname)
    {
        return false;
    }

    virtual bool addTunnelRoute(IpPrefix& ipPrefix, tunnelEndpoint& endp)
    {
        return false;
    }

    void setPeerList(set<string>& p_list)
    {
        peer_list_ = p_list;
    }

    const set<string>& getPeerList() const
    {
        return peer_list_;
    }

    string getTunnelName() const
    {
        return tunnel_;
    }

    virtual ~VNetObject() {};

private:
    set<string> peer_list_ = {};
    string tunnel_;
};

class VNetVrfObject : public VNetObject
{
public:
    VNetVrfObject(const string& vnet, string& tunnel, set<string>& peer, vector<sai_attribute_t>& attrs);

    sai_object_id_t getVRidIngress() const;

    sai_object_id_t getVRidEgress() const;

    set<sai_object_id_t> getVRids() const;

    bool createObj(vector<sai_attribute_t>&);

    bool updateObj(vector<sai_attribute_t>&);

    ~VNetVrfObject();

private:
    string vnet_name_;
    vrid_list_t vr_ids_;
};

class VNetBitmapObject: public VNetObject
{
public:
    VNetBitmapObject(const string& vnet, string& tunnel, set<string>& peer, vector<sai_attribute_t>& attrs);


    virtual bool addIntf(Port& port, IpPrefix *prefix);

    virtual bool updateObj(vector<sai_attribute_t>&);

    virtual ~VNetBitmapObject()
    {}

private:
    static uint32_t getFreeBitmapId(const string& name);
    static uint32_t getBitmapId(const string& name);
    static void recycleBitmapId(uint32_t id);
    static uint32_t getFreeVnetTableOffset();
    static void recycleVnetTableOffset(uint32_t offset);
    static uint32_t getFreeTunnelRouteTableOffset();
    static void recycleTunnelRouteTableOffset(uint32_t offset);
    static uint32_t vnetBitmap_;
    static map<string, uint32_t> vnetIds_;
    static set<uint32_t> vnetOffsets_;
    static set<uint32_t> tunnelOffsets_;

    bool addVlan(uint16_t vlan_id);

    set<string> peers_;
    uint32_t vnet_id_;
    string vnet_name_;
};

typedef std::unique_ptr<VNetObject> VNetObject_T;
typedef std::unordered_map<std::string, VNetObject_T> VNetTable;

class VNetOrch : public Orch2
{
public:
    VNetOrch(DBConnector *db, const std::string&);
    virtual ~VNetOrch() {}

    bool isVnetExists(const std::string& name) const
    {
        return vnet_table_.find(name) != std::end(vnet_table_);
    }

    VNetObject * getVnetPtr(const string& name)
    {
        return vnet_table_.at(name).get();
    }

    const set<string>& getPeerList(const std::string& name) const
    {
        return vnet_table_.at(name)->getPeerList();
    }

    string getTunnelName(const std::string& name) const
    {
        return vnet_table_.at(name)->getTunnelName();
    }

    virtual std::unique_ptr<VNetObject> createObject(const string&, string&, set<string>&, vector<sai_attribute_t>&) = 0;

private:
    virtual bool addOperation(const Request& request);
    virtual bool delOperation(const Request& request);

    VNetTable vnet_table_;
    VNetRequest request_;
};

class VNetVrfOrch : public VNetOrch
{
public:
    VNetVrfOrch(DBConnector *db, const std::string&);
    virtual ~VNetVrfOrch() {}

    virtual std::unique_ptr<VNetObject> createObject(const string&, string&, set<string>&, vector<sai_attribute_t>&);
};

class VNetBitmapOrch : public VNetOrch
{
public:
    VNetBitmapOrch(DBConnector *db, const std::string&);
    virtual ~VNetBitmapOrch() {}

    virtual std::unique_ptr<VNetObject> createObject(const string&, string&, set<string>&, vector<sai_attribute_t>&);
};

const request_description_t vnet_route_description = {
    { REQ_T_STRING, REQ_T_IP_PREFIX },
    {
        { "endpoint",    REQ_T_IP },
        { "ifname",      REQ_T_STRING },
        { "vni",         REQ_T_UINT },
        { "mac_address", REQ_T_MAC_ADDRESS },
    },
    { }
};

class VNetRouteRequest : public Request
{
public:
    VNetRouteRequest() : Request(vnet_route_description, ':') { }
};

typedef map<IpAddress, sai_object_id_t> NextHopMap;
typedef map<string, NextHopMap> NextHopTunnels;

class VNetRouteOrch : public Orch2
{
public:
    VNetRouteOrch(DBConnector *db, vector<string> &tableNames, VNetOrch *);

    typedef pair<string, void (VNetRouteOrch::*) (const Request& )> handler_pair;
    typedef map<string, void (VNetRouteOrch::*) (const Request& )> handler_map;

private:
    virtual bool addOperation(const Request& request);
    virtual bool delOperation(const Request& request);

    void handleRoutes(const Request&);
    void handleTunnel(const Request&);

    bool doRouteTask(const string& vnet, IpPrefix& ipPrefix, tunnelEndpoint& endp);

    bool doRouteTask(const string& vnet, IpPrefix& ipPrefix, string& ifname);

    sai_object_id_t getNextHop(const string& vnet, tunnelEndpoint& endp);

    VNetOrch *vnet_orch_;
    VNetRouteRequest request_;
    handler_map handler_map_;
    NextHopTunnels nh_tunnels_;
};

#endif // __VNETORCH_H
