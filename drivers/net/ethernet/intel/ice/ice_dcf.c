// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2020, Intel Corporation. */

#include "ice.h"

static const enum ice_adminq_opc aqc_permitted_tbl[] = {
	/* Generic Firmware Admin commands */
	ice_aqc_opc_get_ver,
	ice_aqc_opc_req_res,
	ice_aqc_opc_release_res,
	ice_aqc_opc_list_func_caps,
	ice_aqc_opc_list_dev_caps,

	/* Package Configuration Admin Commands */
	ice_aqc_opc_update_pkg,
	ice_aqc_opc_get_pkg_info_list,

	/* PHY commands */
	ice_aqc_opc_get_phy_caps,
	ice_aqc_opc_get_link_status,

	/* Switch Block */
	ice_aqc_opc_get_sw_cfg,
	ice_aqc_opc_alloc_res,
	ice_aqc_opc_free_res,
	ice_aqc_opc_add_recipe,
	ice_aqc_opc_recipe_to_profile,
	ice_aqc_opc_get_recipe,
	ice_aqc_opc_get_recipe_to_profile,
	ice_aqc_opc_add_sw_rules,
	ice_aqc_opc_update_sw_rules,
	ice_aqc_opc_remove_sw_rules,
};

/**
 * ice_dcf_aq_cmd_permitted - validate the AdminQ command permitted or not
 * @desc: descriptor describing the command
 */
bool ice_dcf_aq_cmd_permitted(struct ice_aq_desc *desc)
{
	u16 opc = le16_to_cpu(desc->opcode);
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(aqc_permitted_tbl); i++)
		if (opc == aqc_permitted_tbl[i])
			return true;

	return false;
}
