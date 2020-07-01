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

/**
 * ice_check_dcf_allowed - check if DCF is allowed based on various checks
 * @vf: pointer to the VF to check
 */
bool ice_check_dcf_allowed(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	struct device *dev;

	dev = ice_pf_to_dev(pf);

	if (vf->vf_id != ICE_DCF_VFID) {
		dev_err(dev, "VF %d requested DCF capability, but only VF %d is allowed to request DCF capability\n",
			vf->vf_id, ICE_DCF_VFID);
		return false;
	}

	if (!vf->trusted) {
		dev_err(dev, "VF needs to be trusted to configure DCF capability\n");
		return false;
	}

	return true;
}

/**
 * ice_vf_is_dcf - helper to check if the assigned VF is a DCF
 * @vf: the assigned VF to be checked
 */
bool ice_is_vf_dcf(struct ice_vf *vf)
{
	return vf == vf->pf->dcf.vf;
}

/**
 * ice_dcf_get_state - Get DCF state of the associated PF
 * @pf: PF instance
 */
enum ice_dcf_state ice_dcf_get_state(struct ice_pf *pf)
{
	return pf->dcf.vf ? pf->dcf.state : ICE_DCF_STATE_OFF;
}

/**
 * ice_dcf_state_str - convert DCF state code to a string
 * @state: the DCF state code to convert
 */
static const char *ice_dcf_state_str(enum ice_dcf_state state)
{
	switch (state) {
	case ICE_DCF_STATE_OFF:
		return "ICE_DCF_STATE_OFF";
	case ICE_DCF_STATE_ON:
		return "ICE_DCF_STATE_ON";
	case ICE_DCF_STATE_BUSY:
		return "ICE_DCF_STATE_BUSY";
	case ICE_DCF_STATE_PAUSE:
		return "ICE_DCF_STATE_PAUSE";
	}

	return "ICE_DCF_STATE_UNKNOWN";
}

/**
 * ice_dcf_set_state - Set DCF state for the associated PF
 * @pf: PF instance
 * @state: new DCF state
 */
void ice_dcf_set_state(struct ice_pf *pf, enum ice_dcf_state state)
{
	dev_dbg(ice_pf_to_dev(pf), "DCF state is changing from %s to %s\n",
		ice_dcf_state_str(pf->dcf.state),
		ice_dcf_state_str(state));

	pf->dcf.state = state;
}
