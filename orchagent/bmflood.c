#include <stdio.h>
#include <sx/sdk/sx_api_rm.h>
#include <sx/sxd/sxd_access_register_init.h>
#include <sx/sxd/sxd_access_register.h>
#include <sx/sxd/sxd_dpt.h>
#include <errno.h>

#define BRIDGE_START 4998

#define SX_PORT_PHY_ID_MASK  (0x0000FF00)
#define SX_PORT_PHY_ID_ISO(id)  ((id) & (SX_PORT_PHY_ID_MASK))
#define SX_PORT_PHY_ID_OFFS  (8)
#define SX_PORT_PHY_ID_GET(id)  (SX_PORT_PHY_ID_ISO(id) >> SX_PORT_PHY_ID_OFFS)
#define SPECTRUM_PORT_EXT_NUM_MAX (64)
#define SX_ROUTER_PHY_PORT (SPECTRUM_PORT_EXT_NUM_MAX + 2)
#define SX_FDB_ROUTER_PORT(dev_id) ((sx_port_log_id_t)((dev_id << 16) | (SX_ROUTER_PHY_PORT << 8)))


void log_cb(sx_log_severity_t severity, const char *module_name, char *msg)
{
    printf(msg);
}

int main(int argc, char *argv[]) {
    sxd_status_t              sxd_ret = SXD_STATUS_SUCCESS;
    sxd_handle                sxd_handle   = 0;
    uint32_t                  dev_num      = 1;
    char                      dev_name[MAX_NAME_LEN];
    char                     *dev_names[1] = { dev_name };
    struct ku_sftr_reg        sftr_reg_data;
    sxd_reg_meta_t     sftr_reg_meta;
    sx_port_phy_id_t          port_phy_id = 0;

    memset(&sftr_reg_meta, 0, sizeof(sftr_reg_meta));
    memset(&sftr_reg_data, 0, sizeof(sftr_reg_data));

    sxd_ret = sxd_access_reg_init(0, log_cb, 0);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        printf("Failed to init access reg - %s.\n", SXD_STATUS_MSG(sxd_ret));
        return 1;
    }

    /* get device list from the devices directory */
    sxd_ret = sxd_get_dev_list(dev_names, &dev_num);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        printf("sxd_get_dev_list error %s.\n", SXD_STATUS_MSG(sxd_ret));
        return 1;
    }

    /* open the first device */
    sxd_ret = sxd_open_device(dev_name, &sxd_handle);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        printf("sxd_open_device error %s.\n", SXD_STATUS_MSG(sxd_ret));
        return 1;
    }

    printf("Init done.\n");

    sftr_reg_meta.swid = 0;
    sftr_reg_meta.dev_id = 1;
    sftr_reg_meta.access_cmd = SXD_ACCESS_CMD_ADD;

    sftr_reg_data.swid = 0;
    sftr_reg_data.index = BRIDGE_START - 4096;
    sftr_reg_data.range = 0;
    sftr_reg_data.flood_table = 1;
    sftr_reg_data.table_type = SFGC_TABLE_TYPE_FID;
    port_phy_id = SX_PORT_PHY_ID_GET(SX_FDB_ROUTER_PORT(0));
    sftr_reg_data.mask_bitmap[port_phy_id] = 1;
    sftr_reg_data.ports_bitmap[port_phy_id] = 1;

    sxd_ret = sxd_access_reg_sftr(&sftr_reg_data, &sftr_reg_meta, 1, NULL, NULL);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        printf("sxd_access_reg_sftr error %s.\n", SXD_STATUS_MSG(sxd_ret));
        return 1;
    }

    for (int i = -4; i < 2; i++) {
        for (int k = 0; k < 3; k++) {
            sftr_reg_meta.swid = 0;
            sftr_reg_meta.dev_id = 1;
            sftr_reg_meta.access_cmd = SXD_ACCESS_CMD_GET;

            sftr_reg_data.swid = 0;
            sftr_reg_data.index = BRIDGE_START + i - 4096;
            sftr_reg_data.range = 0;
            sftr_reg_data.flood_table = k;
            sftr_reg_data.table_type = SFGC_TABLE_TYPE_FID;
            port_phy_id = SX_PORT_PHY_ID_GET(SX_FDB_ROUTER_PORT(0));
            sftr_reg_data.mask_bitmap[port_phy_id] = 1;
            sftr_reg_data.ports_bitmap[port_phy_id] = 1;

            sxd_ret = sxd_access_reg_sftr(&sftr_reg_data, &sftr_reg_meta, 1, NULL, NULL);
            if (SXD_CHECK_FAIL(sxd_ret)) {
                printf("sxd_access_reg_sftr error %s.\n", SXD_STATUS_MSG(sxd_ret));
                return 1;
            }

            for (int j = 0; j < 0xFF; j++) {
                if (sftr_reg_data.ports_bitmap[j]) {
                    printf("bridge %i port %i table %i bit %d\n", BRIDGE_START + i, j, k, sftr_reg_data.ports_bitmap[j]);
                }
            }
        }
    }

    sxd_ret = sxd_close_device(sxd_handle);
    if (SXD_CHECK_FAIL(sxd_ret)) {
        printf("sxd_close_device error: %s\n", SXD_STATUS_MSG(sxd_ret));
        return 1;
    }

    printf("Set flood to router\n");

    return 0;
}
