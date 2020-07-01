/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2020, Intel Corporation. */

#ifndef _ICE_DCF_H_
#define _ICE_DCF_H_

struct ice_dcf {
	/* Handle the AdminQ command between the DCF (Device Config Function)
	 * and the firmware.
	 */
#define ICE_DCF_AQ_DESC_TIMEOUT	(HZ / 10)
	struct ice_aq_desc aq_desc;
	u8 aq_desc_received;
	unsigned long aq_desc_expires;
};

#ifdef CONFIG_PCI_IOV
bool ice_dcf_aq_cmd_permitted(struct ice_aq_desc *desc);
#endif /* CONFIG_PCI_IOV */
#endif /* _ICE_DCF_H_ */
