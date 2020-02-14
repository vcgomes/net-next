/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * virtual_bus.h - lightweight software bus
 *
 * Copyright (c) 2019-20 Intel Corporation
 *
 * Please see Documentation/driver-api/virtual_bus.rst for more information
 */

#ifndef _VIRTUAL_BUS_H_
#define _VIRTUAL_BUS_H_

#include <linux/device.h>

struct virtbus_device {
	struct device dev;
	const char *name;
	void (*release)(struct virtbus_device *);
	int id;
	const struct virtbus_dev_id *matched_element;
};

/* The memory for the table is expected to remain allocated for the duration
 * of the pairing between driver and device.  The pointer for the matching
 * element will be copied to the matched_element field of the virtbus_device.
 */
struct virtbus_driver {
	int (*probe)(struct virtbus_device *);
	int (*remove)(struct virtbus_device *);
	void (*shutdown)(struct virtbus_device *);
	int (*suspend)(struct virtbus_device *, pm_message_t);
	int (*resume)(struct virtbus_device *);
	struct device_driver driver;
	const struct virtbus_dev_id *id_table;
};

static inline
struct virtbus_device *to_virtbus_dev(struct device *dev)
{
	return container_of(dev, struct virtbus_device, dev);
}

static inline
struct virtbus_driver *to_virtbus_drv(struct device_driver *drv)
{
	return container_of(drv, struct virtbus_driver, driver);
}

int virtbus_dev_register(struct virtbus_device *vdev);
void virtbus_dev_unregister(struct virtbus_device *vdev);
int __virtbus_drv_register(struct virtbus_driver *vdrv, struct module *owner);
void virtbus_drv_unregister(struct virtbus_driver *vdrv);

#define virtbus_drv_register(vdrv) \
	__virtbus_drv_register(vdrv, THIS_MODULE)

#endif /* _VIRTUAL_BUS_H_ */
