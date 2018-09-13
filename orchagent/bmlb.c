/* gcc bmloopback.c -g -std=gnu99 -Wall -lsxnet -lsxapi -lsxcomp -lsxlog -o bmlb*/
#include <stdio.h>
#include <sx/sdk/sx_api.h>
#include <sx/sdk/sx_api_init.h>
#include <sx/sdk/sx_api_acl.h>
#include <sx/sdk/sx_api_port.h>
#include <sx/sdk/sx_api_bridge.h>
#include <sx/sdk/sx_api_router.h>
#include <sx/sdk/sx_api_vlan.h>
#include <sx/sdk/sx_api_fdb.h>
#include<signal.h>
#include<unistd.h>


#define NUM_OF_VNI 900
#define VLAN_START 3
#define BRIDGE_ID_START 4098
#define LB_VLAN 2

struct globals {
    sx_api_handle_t      handle;
    sx_port_log_id_t     loopback_port;
    sx_port_log_id_t     vportvlan_lb;
    sx_port_log_id_t     vportvlan_vm[NUM_OF_VNI];
    sx_bridge_id_t       vm2loopback_bridges[NUM_OF_VNI];
    sx_bridge_id_t       loopback2router;
    sx_router_interface_t         loopback2route_rif;
    uint8_t vmd_mac[6];
    uint8_t router_mac[6]; 
   
};

struct globals g;

void
init()
{
   sx_api_open(NULL, &g.handle);
   g.loopback_port=0x11f00;
   for (int i=0; i< NUM_OF_VNI; i++) {
      g.vm2loopback_bridges[i]=BRIDGE_ID_START + i;
   }
    
}

void
deinit()
{
   sx_api_close(&g.handle);
    
}

void sig_handler(int signo)
{
   if (signo == SIGINT)
   {
           //clean all 
           printf("delete mac from bridge\n");
           //add FDB got router to sloopback2route bridge
           sx_fdb_uc_mac_addr_params_t  mac;
           mac.fid_vid=g.loopback2router;
           memcpy(&mac.mac_addr,g.vmd_mac,6);
           mac.entry_type=SX_FDB_UC_STATIC;
           mac.action=SX_FDB_ACTION_FORWARD_TO_ROUTER; 
           uint32_t cnt=1;
           sx_api_fdb_uc_mac_addr_set(g.handle,SX_ACCESS_CMD_DELETE,0,&mac,&cnt);
           //delete rif 
           printf("delete RIF\n");
           sx_router_interface_param_t  ifp;
           sx_interface_attributes_t    ifa;
           ifp.type=SX_L2_INTERFACE_TYPE_BRIDGE;
           ifp.ifc.bridge.swid=0;
           ifp.ifc.bridge.bridge=g.loopback2router;
        //ifa.mac_addr=my_mac;
           memcpy(&ifa.mac_addr,g.router_mac,6);
           ifa.mtu=9000;
           ifa.qos_mode=0;
           ifa.multicast_ttl_threshold=1;
           ifa.loopback_enable=0;
           sx_api_router_interface_set(g.handle,SX_ACCESS_CMD_DELETE,0,&ifp,&ifa,&g.loopback2route_rif);
           sx_api_vlan_port_pvid_set(g.handle, SX_ACCESS_CMD_DELETE, g.loopback_port, 1);

	   // set vports state to down
 	   sx_port_admin_state_t admin=SX_PORT_ADMIN_STATUS_DOWN;
 	   sx_api_port_state_set(g.handle,g.vportvlan_lb, admin);
           for (int i=0; i< NUM_OF_VNI; i++) {
    	       sx_api_port_state_set(g.handle,g.vportvlan_vm[i], admin);
           }


           //remove vpor2 from  vm2router
           printf("remove vport1 from  bridge\n");
           sx_api_bridge_vport_set(g.handle,SX_ACCESS_CMD_DELETE,g.loopback2router,g.vportvlan_lb);
           
            printf("remove vport vms from  bridge\n");
           for (int i=0; i< NUM_OF_VNI; i++) {
             sx_api_bridge_vport_set(g.handle,SX_ACCESS_CMD_DELETE,g.vm2loopback_bridges[i],g.vportvlan_vm[i]);
           }

           //create bridge loopback to router 
           printf("remove bridge\n");                            
           sx_api_bridge_set(g.handle,SX_ACCESS_CMD_DESTROY,&g.loopback2router);
          //delete vports 
           sx_api_port_vport_set(g.handle,SX_ACCESS_CMD_DELETE,g.loopback_port,LB_VLAN, &g.vportvlan_lb);
           for (int i=0; i< NUM_OF_VNI; i++) {
            sx_api_port_vport_set(g.handle,SX_ACCESS_CMD_DELETE,g.loopback_port,VLAN_START + i,&g.vportvlan_vm[i]);
          }
           exit(0);
    }
}


int
main()
{
    init();
    //uint8_t vmd_mac[]={0x00,0x15,0x5d,0x01,0x01,0x00};
    uint8_t vmd_mac[]={0x24,0x8a,0x07,0x1e,0xde,0xa8};
    //uint8_t router_mac[]={0x7c,0xfe,0x90,0x6d,0xb9,0x40}; 
    uint8_t router_mac[]={0x24,0x8a,0x07,0x28,0x52,0x00}; 
    memmove(g.vmd_mac,vmd_mac,sizeof(vmd_mac));
    memmove(g.router_mac,router_mac,sizeof(router_mac));
    signal(SIGINT, sig_handler);  
    //create port loopbak on port 6 
    sx_port_phys_loopback_t phys_loopback=SX_PORT_PHYS_LOOPBACK_ENABLE_INTERNAL;
    sx_status_t rc = sx_api_port_phys_loopback_set(g.handle,g.loopback_port,phys_loopback);
    if (rc) {
  printf("error in sx_api_routetr_interface_set. rc = %d\n",rc);
    }

    //enable port 6
    sx_port_admin_state_t admin=SX_PORT_ADMIN_STATUS_UP;
    rc = sx_api_port_state_set(g.handle,g.loopback_port,admin);
    if (rc) {
  printf("error in sx_api_port_state_set. rc = %d\n",rc);
    }

    rc = sx_api_vlan_port_pvid_set(g.handle, SX_ACCESS_CMD_ADD, g.loopback_port, LB_VLAN);
    if (rc) {
  printf("error in sx_api_vlan_port_pvid_set. rc = %d\n",rc);
    }


    //create vport on port 6 vlan 3+
    for (int i=0; i< NUM_OF_VNI; i++) {
      rc = sx_api_port_vport_set(g.handle,SX_ACCESS_CMD_ADD,g.loopback_port,VLAN_START + i,&g.vportvlan_vm[i]);
      if (rc) {
        printf("error in sx_api_port_vport_set (%d). rc = %d\n", VLAN_START + i, rc);
      }
    }

   //create vport on port 6 vlan LB_VLAN
    rc = sx_api_port_vport_set(g.handle,SX_ACCESS_CMD_ADD,g.loopback_port, LB_VLAN, &g.vportvlan_lb);
    if (rc) {
  printf("error in sx_api_port_vport_set (LB_VLAN). rc = %d\n", rc);
    }

    //create bridge loopback to router                             
     rc = sx_api_bridge_set(g.handle,SX_ACCESS_CMD_CREATE,&g.loopback2router);
     if (rc) {
  printf("error in sx_api_bridge_set. rc = %d\n",rc);
    }

   printf("Created bridge lb2router %d\n", g.loopback2router);
   //add vport2 to  vm2loopback_bridges
  for (int i=0; i< NUM_OF_VNI; i++) {
     rc = sx_api_bridge_vport_set(g.handle, SX_ACCESS_CMD_ADD, g.vm2loopback_bridges[i], g.vportvlan_vm[i]);
     if (rc) {
      printf("error in sx_api_bridge_vport_set (%d). rc = %d\n",i, rc);
    }
  }
    //add vport1 to  loopback2router
     rc = sx_api_bridge_vport_set(g.handle,SX_ACCESS_CMD_ADD,g.loopback2router,g.vportvlan_lb); 
     if (rc) {
  printf("error in sx_api_bridge_vport_set. rc = %d\n",rc);
    }
    // enable vports
    rc = sx_api_port_state_set(g.handle,g.vportvlan_lb, admin);
    if (rc) {
  printf("error in sx_api_port_state_set. rc = %d\n",rc);
    }
    for (int i=0; i< NUM_OF_VNI; i++) {
      rc = sx_api_port_state_set(g.handle,g.vportvlan_vm[i], admin);
      if (rc) {
    printf("error in sx_api_port_state_set (%d). rc = %d\n",i, rc);
      }
    }

    // add port 6 to vlan 2
    sx_vlan_ports_t vlan_port_list;
    vlan_port_list.log_port = g.loopback_port;
    vlan_port_list.is_untagged = SX_UNTAGGED_MEMBER;
    for (int i=0; i< NUM_OF_VNI; i++) {
      rc = sx_api_vlan_ports_set(g.handle, SX_ACCESS_CMD_ADD, 0, VLAN_START + i, &vlan_port_list, 1);
      if (rc) {
        printf("error in sx_api_vlan_ports_set. rc = %d\n",rc);
      } 
    }

    //create RIF for  oopback2router bridge 
    sx_router_interface_param_t  ifp;
    sx_interface_attributes_t    ifa;
    ifp.type=SX_L2_INTERFACE_TYPE_BRIDGE;
    ifp.ifc.bridge.swid=0;
    ifp.ifc.bridge.bridge=g.loopback2router;
    //ifa.mac_addr=my_mac;
    memcpy(&ifa.mac_addr,g.router_mac,6);
    ifa.mtu=9000;
    ifa.qos_mode=0;
    ifa.multicast_ttl_threshold=1;
    ifa.loopback_enable=0;
    rc = sx_api_router_interface_set(g.handle,SX_ACCESS_CMD_ADD,0,&ifp,&ifa,&g.loopback2route_rif);
    if (rc) {
	printf("error in sx_api_router_interface_set. rc = %d\n",rc);
    } else {
	printf("successfully created rif 0x%x", g.loopback2route_rif);
    }

    // enable RIF
    sx_router_interface_state_t rif_state;
    rif_state.ipv4_enable = 1;
    rif_state.ipv4_mc_enable = 0;
    rif_state.ipv6_enable = 1;
    rif_state.ipv6_mc_enable = 0;
    rif_state.mpls_enable = 0;
    rc = sx_api_router_interface_state_set(g.handle, g.loopback2route_rif, &rif_state);
    if (rc) {
  printf("error in sx_api_router_interface_state_set. rc = %d\n",rc);
    } 

    //add FDB got router to sloopback2route bridge
    /* sx_fdb_uc_mac_addr_params_t  mac; */
    /* mac.fid_vid=g.loopback2router; */
    /* memcpy(&mac.mac_addr,g.vmd_mac,6); */
    /* //mac.mac_addr={0x24,0x8a,0x07,0x28,0x52,0x00}; */
    /* mac.entry_type=SX_FDB_UC_STATIC; */
    /* mac.action=SX_FDB_ACTION_FORWARD_TO_ROUTER; */ 
    /* uint32_t cnt=1; */
    /* rc = sx_api_fdb_uc_mac_addr_set(g.handle,SX_ACCESS_CMD_ADD,0,&mac,&cnt); */
    /* if (rc) { */
  /* printf("error in sx_api_routetr_interface_set. rc = %d\n",rc); */
    /* } */ 

                                       
                                                                         
      while(1)
             sleep(100000);                                                      
                                                           
                                      
    deinit();
    return 0;
}
