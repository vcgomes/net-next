/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2020, Intel Corporation. */

#ifndef _ICE_DCF_H_
#define _ICE_DCF_H_

struct ice_vf;
struct ice_pf;

#define ICE_DCF_VFID	0

/* DCF mode states */
enum ice_dcf_state {
	/* DCF mode is fully off */
	ICE_DCF_STATE_OFF = 0,
	/* Process is live, acquired capability to send DCF CMD */
	ICE_DCF_STATE_ON,
	/* Kernel is busy, deny DCF CMD */
	ICE_DCF_STATE_BUSY,
	/* Kernel is ready for Process to Re-establish, deny DCF CMD */
	ICE_DCF_STATE_PAUSE,
};

struct ice_dcf {
	struct ice_vf *vf;
	enum ice_dcf_state state;

	/* Handle the AdminQ command between the DCF (Device Config Function)
	 * and the firmware.
	 */
#define ICE_DCF_AQ_DESC_TIMEOUT	(HZ / 10)
	struct ice_aq_desc aq_desc;
	u8 aq_desc_received;
	unsigned long aq_desc_expires;

	/* Save the current Device Serial Number when searching the package
	 * path for later query.
	 */
#define ICE_DSN_NUM_LEN 8
	u8 dsn[ICE_DSN_NUM_LEN];
};

#ifdef CONFIG_PCI_IOV
bool ice_dcf_aq_cmd_permitted(struct ice_aq_desc *desc);
bool ice_check_dcf_allowed(struct ice_vf *vf);
bool ice_is_vf_dcf(struct ice_vf *vf);
enum ice_dcf_state ice_dcf_get_state(struct ice_pf *pf);
void ice_dcf_set_state(struct ice_pf *pf, enum ice_dcf_state state);
#endif /* CONFIG_PCI_IOV */
#endif /* _ICE_DCF_H_ */
