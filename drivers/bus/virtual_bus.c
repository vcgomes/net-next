// SPDX-License-Identifier: GPL-2.0
/*
 * virtual_bus.c - lightweight software based bus for virtual devices
 *
 * Copyright (c) 2019-20 Intel Corporation
 *
 * Please see Documentation/driver-api/virtual_bus.rst for
 * more information
 */

#include <linux/string.h>
#include <linux/virtual_bus.h>
#include <linux/of_irq.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pm_runtime.h>
#include <linux/pm_domain.h>
#include <linux/acpi.h>
#include <linux/device.h>

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Lightweight Virtual Bus");
MODULE_AUTHOR("David Ertman <david.m.ertman@intel.com>");
MODULE_AUTHOR("Kiran Patil <kiran.patil@intel.com>");

static DEFINE_IDA(virtbus_dev_ida);

static const
struct virtbus_dev_id *virtbus_match_id(const struct virtbus_dev_id *id,
					struct virtbus_device *vdev)
{
	while (id->name[0]) {
		if (!strcmp(vdev->name, id->name)) {
			vdev->matched_element = id;
			return id;
		}
		id++;
	}
	return NULL;
}

static int virtbus_match(struct device *dev, struct device_driver *drv)
{
	struct virtbus_driver *vdrv = to_virtbus_drv(drv);
	struct virtbus_device *vdev = to_virtbus_dev(dev);

	return virtbus_match_id(vdrv->id_table, vdev) != NULL;
}

static int virtbus_probe(struct device *dev)
{
	return dev->driver->probe(dev);
}

static int virtbus_remove(struct device *dev)
{
	return dev->driver->remove(dev);
}

static void virtbus_shutdown(struct device *dev)
{
	dev->driver->shutdown(dev);
}

static int virtbus_suspend(struct device *dev, pm_message_t state)
{
	if (dev->driver->suspend)
		return dev->driver->suspend(dev, state);

	return 0;
}

static int virtbus_resume(struct device *dev)
{
	if (dev->driver->resume)
		return dev->driver->resume(dev);

	return 0;
}

struct bus_type virtual_bus_type = {
	.name = "virtbus",
	.match = virtbus_match,
	.probe = virtbus_probe,
	.remove = virtbus_remove,
	.shutdown = virtbus_shutdown,
	.suspend = virtbus_suspend,
	.resume = virtbus_resume,
};

/**
 * virtbus_dev_release - Destroy a virtbus device
 * @vdev: virtual device to release
 */
static void virtbus_dev_release(struct device *_dev)
{
	struct virtbus_device *vdev = to_virtbus_dev(_dev);

	ida_simple_remove(&virtbus_dev_ida, vdev->id);
	vdev->release(vdev);
}

/**
 * virtbus_dev_register - add a virtual bus device
 * @vdev: virtual bus device to add
 */
int virtbus_dev_register(struct virtbus_device *vdev)
{
	int ret;

	if (!vdev->release) {
		dev_err(&vdev->dev, "virtbus_device .release callback NULL\n");
		return -EINVAL;
	}

	device_initialize(&vdev->dev);

	vdev->dev.bus = &virtual_bus_type;
	vdev->dev.release = virtbus_dev_release;
	/* All device IDs are automatically allocated */
	ret = ida_simple_get(&virtbus_dev_ida, 0, 0, GFP_KERNEL);
	if (ret < 0) {
		dev_err(&vdev->dev, "get IDA idx for virtbus device failed!\n");
		put_device(&vdev->dev);
		return ret;
	}

	vdev->id = ret;
	dev_set_name(&vdev->dev, "%s.%d", vdev->name, vdev->id);

	dev_dbg(&vdev->dev, "Registering virtbus device '%s'\n",
		dev_name(&vdev->dev));

	ret = device_add(&vdev->dev);
	if (ret)
		goto device_add_err;

	return 0;

device_add_err:
	dev_err(&vdev->dev, "Add device to virtbus failed!\n");
	put_device(&vdev->dev);
	ida_simple_remove(&virtbus_dev_ida, vdev->id);

	return ret;
}
EXPORT_SYMBOL_GPL(virtbus_dev_register);

/**
 * virtbus_dev_unregister - remove a virtual bus device
 * vdev: virtual bus device we are removing
 */
void virtbus_dev_unregister(struct virtbus_device *vdev)
{
	device_del(&vdev->dev);
	put_device(&vdev->dev);
}
EXPORT_SYMBOL_GPL(virtbus_dev_unregister);

static int virtbus_drv_probe(struct device *_dev)
{
	struct virtbus_driver *vdrv = to_virtbus_drv(_dev->driver);
	struct virtbus_device *vdev = to_virtbus_dev(_dev);
	int ret;

	ret = dev_pm_domain_attach(_dev, true);
	if (ret) {
		dev_warn(_dev, "Failed to attatch to PM Domain : %d\n", ret);
		return ret;
	}

	ret = vdrv->probe(vdev);
	if (ret) {
		dev_err(&vdev->dev, "Probe returned error\n");
		dev_pm_domain_detach(_dev, true);
	}

	return ret;
}

static int virtbus_drv_remove(struct device *_dev)
{
	struct virtbus_driver *vdrv = to_virtbus_drv(_dev->driver);
	struct virtbus_device *vdev = to_virtbus_dev(_dev);
	int ret = 0;

	ret = vdrv->remove(vdev);
	dev_pm_domain_detach(_dev, true);

	return ret;
}

static void virtbus_drv_shutdown(struct device *_dev)
{
	struct virtbus_driver *vdrv = to_virtbus_drv(_dev->driver);
	struct virtbus_device *vdev = to_virtbus_dev(_dev);

	vdrv->shutdown(vdev);
}

static int virtbus_drv_suspend(struct device *_dev, pm_message_t state)
{
	struct virtbus_driver *vdrv = to_virtbus_drv(_dev->driver);
	struct virtbus_device *vdev = to_virtbus_dev(_dev);

	if (vdrv->suspend)
		return vdrv->suspend(vdev, state);

	return 0;
}

static int virtbus_drv_resume(struct device *_dev)
{
	struct virtbus_driver *vdrv = to_virtbus_drv(_dev->driver);
	struct virtbus_device *vdev = to_virtbus_dev(_dev);

	if (vdrv->resume)
		return vdrv->resume(vdev);

	return 0;
}

/**
 * __virtbus_drv_register - register a driver for virtual bus devices
 * @vdrv: virtbus_driver structure
 * @owner: owning module/driver
 */
int __virtbus_drv_register(struct virtbus_driver *vdrv, struct module *owner)
{
	if (!vdrv->probe || !vdrv->remove || !vdrv->shutdown || !vdrv->id_table)
		return -EINVAL;

	vdrv->driver.owner = owner;
	vdrv->driver.bus = &virtual_bus_type;
	vdrv->driver.probe = virtbus_drv_probe;
	vdrv->driver.remove = virtbus_drv_remove;
	vdrv->driver.shutdown = virtbus_drv_shutdown;
	vdrv->driver.suspend = virtbus_drv_suspend;
	vdrv->driver.resume = virtbus_drv_resume;

	return driver_register(&vdrv->driver);
}
EXPORT_SYMBOL_GPL(__virtbus_drv_register);

/**
 * virtbus_drv_unregister - unregister a driver for virtual bus devices
 * @drv: virtbus_driver structure
 */
void virtbus_drv_unregister(struct virtbus_driver *vdrv)
{
	driver_unregister(&vdrv->driver);
}
EXPORT_SYMBOL_GPL(virtbus_drv_unregister);

static int __init virtual_bus_init(void)
{
	return bus_register(&virtual_bus_type);
}

static void __exit virtual_bus_exit(void)
{
	bus_unregister(&virtual_bus_type);
	ida_destroy(&virtbus_dev_ida);
}

module_init(virtual_bus_init);
module_exit(virtual_bus_exit);
