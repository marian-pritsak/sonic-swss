extern "C" {
#include "sai.h"
#include "saistatus.h"
}

#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <thread>
#include <chrono>
#include <getopt.h>
#include <unistd.h>

#include <sys/time.h>
#include "timestamp.h"

#include <sairedis.h>
#include <logger.h>

#include "orchdaemon.h"
#include "saihelper.h"
#include "notifications.h"
#include <signal.h>

#include "bmt_common.h"

using namespace std;
using namespace swss;

extern sai_switch_api_t *sai_switch_api;
// extern sai_tunnel_api_t *sai_tunnel_api;
// extern sai_bmtor_api_t *sai_bmtor_api;
// extern sai_port_api_t *sai_port_api;
extern sai_router_interface_api_t *sai_router_intfs_api;

#define UNREFERENCED_PARAMETER(P)       (P)

/* Global variables */
sai_object_id_t gVirtualRouterId;
sai_object_id_t gUnderlayIfId;
sai_object_id_t gSwitchId = SAI_NULL_OBJECT_ID;
// sai_object_id_t default_vhost_table_entry;
MacAddress gMacAddress;

#define DEFAULT_BATCH_SIZE  128
int gBatchSize = DEFAULT_BATCH_SIZE;

bool gSairedisRecord = true;
bool gSwssRecord = true;
bool gLogRotate = false;
ofstream gRecordOfs;
string gRecordFile;

bool gExitFlag     = false;
bool gScanDpdkPort = true;


/* Global database mutex */
mutex gDbMutex;

void usage()
{
    cout << "usage: orchagent [-h] [-r record_type] [-d record_location] [-b batch_size] [-m MAC]" << endl;
    cout << "    -h: display this message" << endl;
    cout << "    -r record_type: record orchagent logs with type (default 3)" << endl;
    cout << "                    0: do not record logs" << endl;
    cout << "                    1: record SAI call sequence as sairedis.rec" << endl;
    cout << "                    2: record SwSS task sequence as swss.rec" << endl;
    cout << "                    3: enable both above two records" << endl;
    cout << "    -d record_location: set record logs folder location (default .)" << endl;
    cout << "    -b batch_size: set consumer table pop operation batch size (default 128)" << endl;
    cout << "    -m MAC: set switch MAC address" << endl;
}

void sighup_handler(int signo)
{
    /*
     * Don't do any logging since they are using mutexes.
     */
    gLogRotate = true;

    sai_attribute_t attr;
    attr.id = SAI_REDIS_SWITCH_ATTR_PERFORM_LOG_ROTATE;
    attr.value.booldata = true;

    if (sai_switch_api != NULL)
    {
        sai_switch_api->set_switch_attribute(gSwitchId, &attr);
    }
}

void sig_handler(int signo){
    if (signo == SIGINT){
       gScanDpdkPort=false;
       gExitFlag=true;

    } 
}

// sai_object_id_t
//     sai_get_port_id_by_front_port(uint32_t hw_port)
// {
//   sai_object_id_t new_objlist[32]; //TODO change back to getting from switch
//   sai_attribute_t sai_attr;
//   sai_attr.id = SAI_SWITCH_ATTR_PORT_NUMBER;
//   // sai_switch_api->get_swi tch_attribute(switch_id, 1, &sai_attr);
//   uint32_t max_ports = 32; //sai_attr.value.u32;

//   sai_attr.id = SAI_SWITCH_ATTR_PORT_LIST;
//   //sai_attr.value.objlist.list = (sai_object_id_t *) malloc(sizeof(sai_object_id_t) * max_ports);
//   sai_attr.value.objlist.count = max_ports;
//   sai_attr.value.objlist.list = &new_objlist[0];
//   sai_switch_api->get_switch_attribute(gSwitchId, 1, &sai_attr);
//   // printf("port list\n");

//   sai_attribute_t hw_lane_list_attr;

//   for (uint32_t i = 0; i < max_ports; i++)
//   {
//     uint32_t hw_port_list[4];
//     hw_lane_list_attr.id = SAI_PORT_ATTR_HW_LANE_LIST;
//     hw_lane_list_attr.value.u32list.list = &hw_port_list[0];
//     hw_lane_list_attr.value.u32list.count = 4;
//     // printf("port sai_object_id 0x%" PRIx64 " \n", sai_attr.value.objlist.list[i]);
//     sai_port_api->get_port_attribute(sai_attr.value.objlist.list[i], 1,
//                                  &hw_lane_list_attr);
//     // printf("hw lanes: %d %d %d %d\n", hw_port_list[0], hw_port_list[1], hw_port_list[2], hw_port_list[3]);
//     if (hw_port_list[0] == ((hw_port - 1) * 4)) // Front panel 1 is 0, 2 is 4, 3 is 8, etc.. (room is left for splits)
//     {
//       // free(hw_lane_list_attr.value.u32list.list);
//       // free(sai_attr.value.objlist.list);
//       return sai_attr.value.objlist.list[i];
//     }
//     // free(hw_lane_list_attr.value.u32list.list);
//   }
//   // free(sai_attr.value.objlist.list);
//   SWSS_LOG_ERROR("Failed to get port %d sai_object_id", hw_port);
//   throw "BMToR initialization failure";
//   return -1;
// }

// void print_stats_loop() {
//     int j;
//     sai_bmtor_stat_t counter_ids[2];
//     counter_ids[0] = SAI_BMTOR_STAT_TABLE_VHOST_HIT_PACKETS;
//     counter_ids[1] = SAI_BMTOR_STAT_TABLE_VHOST_HIT_OCTETS;
//     uint64_t counters[2];
//     sai_status_t status;
//     for (j=0; j<100; j++) {
//         std::this_thread::sleep_for(std::chrono::seconds(30));
//         SWSS_LOG_NOTICE("Reading counters\n");
//         status = sai_bmtor_api->get_bmtor_stats(default_vhost_table_entry, 2, counter_ids, counters);
//         if (status != SAI_STATUS_SUCCESS) {
//             SWSS_LOG_ERROR("Failed to read table_vhost default entry counters");
//             throw "BMToR counters read failure";
//         }
//         SWSS_LOG_NOTICE("%d: Cache miss (DPDK):\n Packets: %" PRId64 ".    Bytes: %" PRId64 ".\n", j, counters[0], counters[1]);
//     }
// }

// void init_bmtor() {
//     SWSS_LOG_NOTICE("init_bmtor: wait 30 seconds");
//     std::this_thread::sleep_for(std::chrono::seconds(30));
//     SWSS_LOG_NOTICE("init_bmtor: started");
//     sai_object_id_t dpdk_port = sai_get_port_id_by_front_port(7);
//     sai_attribute_t vhost_table_entry_attr[8];
//     vhost_table_entry_attr[0].id = SAI_TABLE_VHOST_ENTRY_ATTR_ACTION;
//     vhost_table_entry_attr[0].value.s32 = SAI_TABLE_VHOST_ENTRY_ACTION_TO_PORT;
//     vhost_table_entry_attr[1].id = SAI_TABLE_VHOST_ENTRY_ATTR_PORT_ID;
//     vhost_table_entry_attr[1].value.oid = dpdk_port;
//     vhost_table_entry_attr[2].id = SAI_TABLE_VHOST_ENTRY_ATTR_IS_DEFAULT;
//     vhost_table_entry_attr[2].value.booldata = true;
//     // Patch. TODO: need to add condition in header
//     vhost_table_entry_attr[3].id = SAI_TABLE_VHOST_ENTRY_ATTR_PRIORITY; 
//     vhost_table_entry_attr[3].value.u32 = 0;
//     vhost_table_entry_attr[4].id = SAI_TABLE_VHOST_ENTRY_ATTR_META_REG_KEY;
//     vhost_table_entry_attr[4].value.u32 = 0;
//     vhost_table_entry_attr[5].id = SAI_TABLE_VHOST_ENTRY_ATTR_META_REG_MASK;
//     vhost_table_entry_attr[5].value.u32 = 0;
//     vhost_table_entry_attr[6].id = SAI_TABLE_VHOST_ENTRY_ATTR_DST_IP;
//     vhost_table_entry_attr[6].value.u32 = 0;

//     sai_status_t status = sai_bmtor_api->create_table_vhost_entry(&default_vhost_table_entry, gSwitchId, 7, vhost_table_entry_attr);
//     if (status != SAI_STATUS_SUCCESS) {
//         SWSS_LOG_ERROR("Failed to create table_vhost default entry");
//         throw "BMToR initialization failure";
//     }
//     print_stats_loop();
// }

int main(int argc, char **argv)
{
    swss::Logger::linkToDbNative("orchagent");

    SWSS_LOG_ENTER();

    if (signal(SIGHUP, sighup_handler) == SIG_ERR)
    {
        SWSS_LOG_ERROR("failed to setup SIGHUP action");
        exit(1);
    }
    signal(SIGINT, sig_handler); // bmt_addition
    int opt;
    sai_status_t status;

    string record_location = ".";

    while ((opt = getopt(argc, argv, "b:m:r:d:h")) != -1)
    {
        switch (opt)
        {
        case 'b':
            gBatchSize = atoi(optarg);
            break;
        case 'm':
            gMacAddress = MacAddress(optarg);
            break;
        case 'r':
            if (!strcmp(optarg, "0"))
            {
                gSairedisRecord = false;
                gSwssRecord = false;
            }
            else if (!strcmp(optarg, "1"))
            {
                gSwssRecord = false;
            }
            else if (!strcmp(optarg, "2"))
            {
                gSairedisRecord = false;
            }
            else if (!strcmp(optarg, "3"))
            {
                continue; /* default behavior */
            }
            else
            {
                usage();
                exit(EXIT_FAILURE);
            }
            break;
        case 'd':
            record_location = optarg;
            if (access(record_location.c_str(), W_OK))
            {
                SWSS_LOG_ERROR("Failed to access writable directory %s", record_location.c_str());
                exit(EXIT_FAILURE);
            }
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        default: /* '?' */
            exit(EXIT_FAILURE);
        }
    }

    SWSS_LOG_NOTICE("--- Starting Orchestration Agent ---");

    initSaiApi();
    initSaiRedis(record_location);

    sai_attribute_t attr;
    vector<sai_attribute_t> attrs;

    attr.id = SAI_SWITCH_ATTR_INIT_SWITCH;
    attr.value.booldata = true;
    attrs.push_back(attr);

    attr.id = SAI_SWITCH_ATTR_FDB_EVENT_NOTIFY;
    attr.value.ptr = (void *)on_fdb_event;
    attrs.push_back(attr);

    /* Disable/enable SwSS recording */
    if (gSwssRecord)
    {
        gRecordFile = record_location + "/" + "swss.rec";
        gRecordOfs.open(gRecordFile, std::ofstream::out | std::ofstream::app);
        if (!gRecordOfs.is_open())
        {
            SWSS_LOG_ERROR("Failed to open SwSS recording file %s", gRecordFile.c_str());
            exit(EXIT_FAILURE);
        }
        gRecordOfs << getTimestamp() << "|recording started" << endl;
    }

    attr.id = SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY;
    attr.value.ptr = (void *)on_port_state_change;
    attrs.push_back(attr);

    attr.id = SAI_SWITCH_ATTR_SHUTDOWN_REQUEST_NOTIFY;
    attr.value.ptr = (void *)on_switch_shutdown_request;
    attrs.push_back(attr);

    if (gMacAddress)
    {
        attr.id = SAI_SWITCH_ATTR_SRC_MAC_ADDRESS;
        memcpy(attr.value.mac, gMacAddress.getMac(), 6);
        attrs.push_back(attr);
    }

    status = sai_switch_api->create_switch(&gSwitchId, (uint32_t)attrs.size(), attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create a switch, rv:%d", status);
        exit(EXIT_FAILURE);
    }
    SWSS_LOG_NOTICE("Create a switch");

    /* Get switch source MAC address if not provided */
    if (!gMacAddress)
    {
        attr.id = SAI_SWITCH_ATTR_SRC_MAC_ADDRESS;
        status = sai_switch_api->get_switch_attribute(gSwitchId, 1, &attr);
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to get MAC address from switch, rv:%d", status);
            exit(EXIT_FAILURE);
        }
        else
        {
            gMacAddress = attr.value.mac;
        }
    }

    /* Get the default virtual router ID */
    attr.id = SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID;

    status = sai_switch_api->get_switch_attribute(gSwitchId, 1, &attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Fail to get switch virtual router ID %d", status);
        exit(EXIT_FAILURE);
    }

    gVirtualRouterId = attr.value.oid;
    SWSS_LOG_NOTICE("Get switch virtual router ID %lx", gVirtualRouterId);

    /* Create a loopback underlay router interface */
    vector<sai_attribute_t> underlay_intf_attrs;

    sai_attribute_t underlay_intf_attr;
    underlay_intf_attr.id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
    underlay_intf_attr.value.oid = gVirtualRouterId;
    underlay_intf_attrs.push_back(underlay_intf_attr);

    underlay_intf_attr.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
    underlay_intf_attr.value.s32 = SAI_ROUTER_INTERFACE_TYPE_LOOPBACK;
    underlay_intf_attrs.push_back(underlay_intf_attr);

    status = sai_router_intfs_api->create_router_interface(&gUnderlayIfId, gSwitchId, (uint32_t)underlay_intf_attrs.size(), underlay_intf_attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create underlay router interface %d", status);
        exit(EXIT_FAILURE);
    }

    SWSS_LOG_NOTICE("Created underlay router interface ID %lx", gUnderlayIfId);

    /* Initialize orchestration components */
    DBConnector *appl_db = new DBConnector(APPL_DB, DBConnector::DEFAULT_UNIXSOCKET, 0);
    DBConnector *config_db = new DBConnector(CONFIG_DB, DBConnector::DEFAULT_UNIXSOCKET, 0);

    OrchDaemon *orchDaemon = new OrchDaemon(appl_db, config_db);
    if (!orchDaemon->init())
    {
        SWSS_LOG_ERROR("Failed to initialize orchstration daemon");
        exit(EXIT_FAILURE);
    }

    bmt_cache_start();

    try
    {
        SWSS_LOG_NOTICE("Notify syncd APPLY_VIEW");

        attr.id = SAI_REDIS_SWITCH_ATTR_NOTIFY_SYNCD;
        attr.value.s32 = SAI_REDIS_NOTIFY_SYNCD_APPLY_VIEW;
        status = sai_switch_api->set_switch_attribute(gSwitchId, &attr);

        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to notify syncd APPLY_VIEW %d", status);
            exit(EXIT_FAILURE);
        }
        // std::thread t1(init_bmtor);
        orchDaemon->start();
        // t1.join();
    }
    catch (char const *e)
    {
        SWSS_LOG_ERROR("Exception: %s", e);
    }
    catch (exception& e)
    {
        SWSS_LOG_ERROR("Failed due to exception: %s", e.what());
    }

    /** bmt main */
    // bmt_init_status_t bmt_common_init;
    // memset(&bmt_common_init, 0, sizeof(bmt_common_init));
    // if (bmt_init(&bmt_common_init) != 0){
    //     cout << "bmt app will not run. SWSS still running." << endl;
    //     exit(1);
    // }
    gExitFlag      = false;
    gScanDpdkPort  = true;
    // char cache_toggle;
    // while (!gExitFlag){
        cout << ">>> BM TOR demo running. Type 'c' to toggle spectrum cache. ctrl+c to exit." << endl;
        // cin >> cache_toggle;
        // if (cache_toggle == 'c') {
        //     gScanDpdkPort = !gScanDpdkPort;
        //     cout << ">>> toggeling cache state to " << gScanDpdkPort << endl;
            // if (gScanDpdkPort){
/*
              thread t1_cache_inserter(bmt_cache_inserter);
              thread t2_cache_evacuator(bmt_cache_evacuator);
              t1_cache_inserter.detach();
              t2_cache_evacuator.detach();
*/
               
    //         }
    //     }
    //     else if (cin.fail() || cache_toggle != 'c'){
    //       cin.clear();
    //       cin.ignore();
    //       cout << ">>> Incorrect entry."<<endl;
    //       cout << ">>> BM TOR demo running. Type 'c' to toggle spectrum cache. ctrl+c to exit." << endl;
    //     }
    // }
    // bmt_deinit(&bmt_common_init);
    return 0;
}
