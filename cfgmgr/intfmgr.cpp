#include <string.h>
#include "logger.h"
#include "dbconnector.h"
#include "producerstatetable.h"
#include "tokenize.h"
#include "ipprefix.h"
#include "intfmgr.h"
#include "exec.h"
#include "shellcmd.h"

using namespace std;
using namespace swss;

#define VLAN_PREFIX         "Vlan"
#define LAG_PREFIX          "PortChannel"
#define VNET_PREFIX         "Vnet"

#define STATE_VRF_TABLE_NAME "VRF_TABLE"

IntfMgr::IntfMgr(DBConnector *cfgDb, DBConnector *appDb, DBConnector *stateDb, const vector<string> &tableNames) :
        Orch(cfgDb, tableNames),
        m_cfgIntfTable(cfgDb, CFG_INTF_TABLE_NAME),
        m_cfgVlanIntfTable(cfgDb, CFG_VLAN_INTF_TABLE_NAME),
        m_statePortTable(stateDb, STATE_PORT_TABLE_NAME),
        m_stateLagTable(stateDb, STATE_LAG_TABLE_NAME),
        m_stateVlanTable(stateDb, STATE_VLAN_TABLE_NAME),
        m_stateVrfTable(stateDb, STATE_VRF_TABLE_NAME),
        m_appIntfTableProducer(appDb, APP_INTF_TABLE_NAME)
{
}

bool IntfMgr::setIntfIp(const string &alias, const string &opCmd,
                        const string &ipPrefixStr, const bool ipv4)
{
    stringstream cmd;
    string res;

    if (ipv4)
    {
        cmd << IP_CMD << " address " << opCmd << " " << ipPrefixStr << " dev " << alias;
    }
    else
    {
        cmd << IP_CMD << " -6 address " << opCmd << " " << ipPrefixStr << " dev " << alias;
    }
    int ret = swss::exec(cmd.str(), res);
    return (ret == 0);
}

bool IntfMgr::setIntfVrf(const string &alias, const string vrfName)
{
    stringstream cmd;
    string res;

    if (!vrfName.empty())
    {
        cmd << IP_CMD << " link set " << alias << " master " << vrfName;
    }
    else
    {
        cmd << IP_CMD << " link set " << alias << " nomaster";
    }
    int ret = swss::exec(cmd.str(), res);
    return (ret == 0);
}

bool IntfMgr::isIntfStateOk(const string &alias)
{
    vector<FieldValueTuple> temp;

    if (!alias.compare(0, strlen(VLAN_PREFIX), VLAN_PREFIX))
    {
        if (m_stateVlanTable.get(alias, temp))
        {
            SWSS_LOG_DEBUG("Vlan %s is ready", alias.c_str());
            return true;
        }
    }
    else if (!alias.compare(0, strlen(LAG_PREFIX), LAG_PREFIX))
    {
        if (m_stateLagTable.get(alias, temp))
        {
            SWSS_LOG_DEBUG("Lag %s is ready", alias.c_str());
            return true;
        }
    }
    else if (!alias.compare(0, strlen(VNET_PREFIX), VNET_PREFIX))
    {
        if (m_stateVrfTable.get(alias, temp))
        {
            SWSS_LOG_DEBUG("Vnet %s is ready", alias.c_str());
            return true;
        }
    }
    else if (m_statePortTable.get(alias, temp))
    {
        SWSS_LOG_DEBUG("Port %s is ready", alias.c_str());
        return true;
    }

    return false;
}
void IntfMgr::doTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;

        vector<string> keys = tokenize(kfvKey(t), config_db_key_delimiter);

        if (keys.size() != 2)
        {
            SWSS_LOG_ERROR("Invalid key %s", kfvKey(t).c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

        const vector<FieldValueTuple>& data = kfvFieldsValues(t);
        string vnet_name = "";

        for (auto idx : data)
        {
            const auto &field = fvField(idx);
            const auto &value = fvValue(idx);
            if (field == "vnet_name")
            {
                vnet_name = value;
            }
        }

        string alias(keys[0]);
        IpPrefix ip_prefix(keys[1]);

        string op = kfvOp(t);
        if (op == SET_COMMAND)
        {
            /*
             * Don't proceed if port/LAG/VLAN is not ready yet.
             * The pending task will be checked periodically and retried.
             * TODO: Subscribe to stateDB for port/lag/VLAN state and retry
             * pending tasks immediately upon state change.
             */
            if (!isIntfStateOk(alias))
            {
                SWSS_LOG_DEBUG("Interface is not ready, skipping %s", kfvKey(t).c_str());
                it++;
                continue;
            }

            if (!vnet_name.empty())
            {
                if (!isIntfStateOk(vnet_name))
                {
                    SWSS_LOG_DEBUG("VRF is not ready, skipping %s", kfvKey(t).c_str());
                    it++;
                    continue;
                }

                setIntfVrf(alias, vnet_name);
            }

            setIntfIp(alias, "add", ip_prefix.to_string(), ip_prefix.isV4());

        }
        else if (op == DEL_COMMAND)
        {
            setIntfVrf(alias, "");
            setIntfIp(alias, "del", ip_prefix.to_string(), ip_prefix.isV4());
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation: %s", op.c_str());
        }

        it = consumer.m_toSync.erase(it);
    }
}
