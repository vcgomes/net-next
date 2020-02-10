/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2016-2019 Intel Corporation. */
#ifndef _GSWIP_CORE_H_
#define _GSWIP_CORE_H_

#include <linux/delay.h>
#include <linux/bitfield.h>
#include <linux/regmap.h>

#include "gswip.h"

/* table should be ready in 30 clock cycle */
#define TBL_BUSY_TIMEOUT_US	1

struct gswip_core_priv {
	struct device *dev;

	unsigned long *br_map;
	unsigned long *br_port_map;
	unsigned long *ctp_port_map;
	void *pdev;

	u8 cpu_port;
	u8 num_lport;
	u8 num_br;
	u8 num_br_port;
	u16 num_ctp;
	u16 num_glb_port;
	u16 num_pmac;
	u16 num_phy_port;
	u16 num_q;

	u16 ver;
	struct regmap *regmap;
	/* table read/write lock */
	spinlock_t tbl_lock;
};

static inline void update_val(u16 *val, u16 mask, u16 set)
{
	*val &= ~mask;
	*val |= FIELD_PREP(mask, set);
}

static inline void reg_r16(struct gswip_core_priv *priv, u16 reg, u16 *val)
{
	unsigned int reg_val;

	regmap_read(priv->regmap, reg, &reg_val);
	*val = reg_val;
}

static inline void reg_wbits(struct gswip_core_priv *priv,
			     u16 reg, u16 mask, u16 val)
{
	regmap_update_bits(priv->regmap, reg, mask, FIELD_PREP(mask, val));
}

static inline u16 reg_rbits(struct gswip_core_priv *priv, u16 reg, u16 mask)
{
	unsigned int reg_val;

	regmap_read(priv->regmap, reg, &reg_val);
	return FIELD_GET(mask, reg_val);
}

/* Access table with timeout */
static inline int tbl_rw_tmout(struct gswip_core_priv *priv, u16 reg, u16 mask)
{
	unsigned int val;

	return regmap_read_poll_timeout(priv->regmap, reg, val, !(val & mask),
					0, TBL_BUSY_TIMEOUT_US);
}

int gswip_cpu_port_cfg_get(struct device *dev, struct gswip_cpu_port_cfg *cpu);
int gswip_enable(struct device *dev, bool enable);

int gswip_register_get(struct device *dev, struct gswip_register *param);
int gswip_register_set(struct device *dev, struct gswip_register *param);

/* PMAC global configuration */
int gswip_pmac_glb_cfg_set(struct device *dev,
			   struct gswip_pmac_glb_cfg *pmac);
/* PMAC backpressure configuration */
int gswip_pmac_bp_map_get(struct device *dev, struct gswip_pmac_bp_map *bp);
/* PMAC ingress configuration */
int gswip_pmac_ig_cfg_set(struct device *dev, struct gswip_pmac_ig_cfg *ig);
/* PMAC egress configuration */
int gswip_pmac_eg_cfg_set(struct device *dev, struct gswip_pmac_eg_cfg *eg);

/* -- Global Port ID/ Logical Port ID --*/
int gswip_lpid2gpid_set(struct device *dev, struct gswip_lpid2gpid *lp2gp);
int gswip_lpid2gpid_get(struct device *dev, struct gswip_lpid2gpid *lp2gp);
int gswip_gpid2lpid_set(struct device *dev, struct gswip_gpid2lpid *gp2lp);
int gswip_gpid2lpid_get(struct device *dev, struct gswip_gpid2lpid *gp2lp);

int gswip_ctp_port_alloc(struct device *dev, struct gswip_ctp_port_info *ctp);
int gswip_ctp_port_free(struct device *dev, u8 lpid);
int gswip_bridge_port_alloc(struct device *dev,
			    struct gswip_br_port_alloc *bp);
int gswip_bridge_port_free(struct device *dev, struct gswip_br_port_alloc *bp);
int gswip_bridge_alloc(struct device *dev, struct gswip_br_alloc *br);
int gswip_bridge_free(struct device *dev, struct gswip_br_alloc *br);
int gswip_qos_q_port_set(struct device *dev, struct gswip_qos_q_port *qport);
#endif
