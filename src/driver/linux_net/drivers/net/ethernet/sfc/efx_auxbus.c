// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for Solarflare and Xilinx network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 * Copyright 2019-2020 Xilinx Inc.
 * Copyright 2020-2024, Advanced Micro Devices, Inc.
 */
#include <linux/xarray.h>
#include <linux/auxiliary_bus.h>
#include "net_driver.h"
#include <linux/sfc/efx_auxbus.h>
#include "nic.h"
#include "efx_client.h"
#include "efx_auxbus_internal.h"

/* Numbers for auxiliary bus devices need to be unique in the host. */
static DEFINE_IDA(efx_auxbus_ida);

/* Driver data for an exposed auxiliary bus device.
 * This structure is created at function probe time, with a separate one
 * for every client type supported. This structure will only exist if a
 * client type is exposed via the auxiliary bus.
 */
struct sfc_auxdev {
	struct efx_client_type_data *client_type;
	struct efx_auxdev auxdev;
};

static
struct efx_probe_data *cdev_to_probe_data(struct efx_auxdev_client *cdev)
{
	struct efx_client *client;

	if (!cdev)
		return NULL;
	client = container_of(cdev, struct efx_client, auxiliary_info);
	return client->client_type->pd;
}

static
struct efx_auxdev_client *efx_auxbus_open(struct auxiliary_device *auxdev,
					  efx_auxdev_event_handler func,
					  unsigned int events_requested)
{
	struct efx_client_type_data *client_type;
	struct efx_auxdev_client *cdev;
	struct efx_probe_data *pd;
	struct efx_client *client;
	struct efx_auxdev *adev;
	struct sfc_auxdev *sdev;

	EFX_WARN_ON_ONCE_PARANOID(!auxdev);
	if (!auxdev || (events_requested && !func))
		return ERR_PTR(-EINVAL);

	adev = to_efx_auxdev(auxdev);
	sdev = container_of(adev, struct sfc_auxdev, auxdev);
	client_type = sdev->client_type;
	pd = client_type->pd;
	client = efx_client_add(pd, client_type->type);
	if (IS_ERR(client))
		return (struct efx_auxdev_client *)client;

	cdev = &client->auxiliary_info;
	cdev->client_id = client->client_id;
	cdev->net_dev = pd->efx.net_dev;
	cdev->auxdev = adev;
	cdev->events_requested = events_requested;
	cdev->event_handler = func;
	return cdev;
}

static void efx_auxbus_close(struct efx_auxdev_client *cdev)
{
	struct efx_client *client;

	if (!cdev)
		return;

	cdev->event_handler = NULL;
	cdev->net_dev = NULL;
	cdev->client_id = 0;
	client = container_of(cdev, struct efx_client, auxiliary_info);
	efx_client_del(client);
}

static int efx_auxbus_fw_rpc(struct efx_auxdev_client *cdev,
			     struct efx_auxdev_rpc *rpc)
{
	struct efx_probe_data *pd = cdev_to_probe_data(cdev);
	int rc;

	if (!pd)
		return -ENODEV;

	rc = efx_mcdi_rpc_quiet(&pd->efx, rpc->cmd,
				(const efx_dword_t *) rpc->inbuf, rpc->inlen,
				(efx_dword_t *) rpc->outbuf, rpc->outlen,
				&rpc->outlen_actual);
	return rc;
}

static int efx_auxbus_filter_insert(struct efx_auxdev_client *cdev,
				    const struct efx_filter_spec *spec,
				    bool replace_equal)
{
	struct efx_probe_data *pd = cdev_to_probe_data(cdev);
	s32 filter_id = efx_filter_insert_filter(&pd->efx,
						 spec, replace_equal);
	if (filter_id >= 0) {
		EFX_WARN_ON_PARANOID(filter_id & ~EFX_FILTER_ID_MASK);
		filter_id |= spec->priority << EFX_FILTER_PRI_SHIFT;
	}
	return filter_id;
}

static int efx_auxbus_filter_remove(struct efx_auxdev_client *cdev,
				    int filter_id)
{
	struct efx_probe_data *pd = cdev_to_probe_data(cdev);

	if (filter_id < 0)
		return -EINVAL;
	return efx_filter_remove_id_safe(&pd->efx,
					 filter_id >> EFX_FILTER_PRI_SHIFT,
					 filter_id & EFX_FILTER_ID_MASK);
}

static int efx_auxbus_filter_get_block(struct efx_nic *efx,
				       enum efx_filter_block_kernel_type type,
				       bool *does_block)
{
	int rc = 0;

	if (!efx || type < 0 || type >= EFX_FILTER_BLOCK_KERNEL_MAX)
		return -EINVAL;

	mutex_lock(&efx->block_kernel_mutex);
	*does_block = (efx->block_kernel_count[type] != 0);
	mutex_unlock(&efx->block_kernel_mutex);

	return rc;
}

static int efx_auxbus_filter_set_block(struct efx_nic *efx,
				       enum efx_filter_block_kernel_type type,
				       bool should_block)
{
	int rc = 0;

	if (!efx || type < 0 || type >= EFX_FILTER_BLOCK_KERNEL_MAX)
		return -EINVAL;

	mutex_lock(&efx->block_kernel_mutex);
	if (should_block) {
		if (efx->block_kernel_count[type] == 0)
			rc = efx->type->filter_block_kernel(efx, type);
		if (rc == 0)
			efx->block_kernel_count[type]++;
	} else {
		if (--efx->block_kernel_count[type] == 0)
			efx->type->filter_unblock_kernel(efx, type);
	}
	mutex_unlock(&efx->block_kernel_mutex);

	return rc;
}

static int efx_auxbus_get_param(struct efx_auxdev_client *handle,
				enum efx_auxiliary_param p,
				union efx_auxiliary_param_value *arg)
{
	struct efx_probe_data *pd;
	struct efx_nic *efx;
	int rc = 0;

	if (!handle || !arg)
		return -EINVAL;

	pd = cdev_to_probe_data(handle);
	if (!pd)
		return -ENODEV;

	efx = &pd->efx;

	switch (p) {
	case EFX_NETDEV:
		arg->net_dev = handle->net_dev;
		break;
	case EFX_MEMBASE:
		arg->membase_addr = handle->membase_addr;
		break;
	case EFX_USE_MSI:
		arg->b = handle->use_msi;
		break;
	case EFX_CHANNELS:
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XARRAY)
		arg->channels = handle->channels;
#else
		rc = -EOPNOTSUPP;
#endif
		break;
	case EFX_RXFH_DEFAULT_FLAGS:
		arg->value = efx_mcdi_get_default_rss_flags(efx);
		break;
	case EFX_DESIGN_PARAM:
		arg->design_params = &handle->design_params;
		break;
	case EFX_PCI_DEVICE:
		arg->value = efx->pci_dev->device;
		break;
	case EFX_DEVICE_REVISION:
		rc = pci_read_config_byte(efx->pci_dev, PCI_CLASS_REVISION,
					  (u8 *)&arg->value);
		break;
	case EFX_TIMER_QUANTUM_NS:
		arg->value = efx->timer_quantum_ns;
		break;
	case EFX_DRIVER_DATA:
		arg->driver_data = handle->driver_data;
		break;
	case EFX_PARAM_FILTER_BLOCK_KERNEL_UCAST:
		rc = efx_auxbus_filter_get_block(efx,
						 EFX_FILTER_BLOCK_KERNEL_UCAST,
						 &arg->b);
		break;
	case EFX_PARAM_FILTER_BLOCK_KERNEL_MCAST:
		rc = efx_auxbus_filter_get_block(efx,
						 EFX_FILTER_BLOCK_KERNEL_MCAST,
						 &arg->b);
		break;
	default:
		rc = -EOPNOTSUPP;
		break;
	}

	return rc;
}

static int efx_auxbus_set_param(struct efx_auxdev_client *handle,
				enum efx_auxiliary_param p,
				union efx_auxiliary_param_value *arg)
{
	struct efx_probe_data *pd;
	struct efx_nic *efx;
	int rc = 0;

	if (!handle || !arg)
		return -EINVAL;

	pd = cdev_to_probe_data(handle);
	if (!pd)
		return -ENODEV;

	efx = &pd->efx;

	switch (p) {
	case EFX_NETDEV:
	case EFX_MEMBASE:
	case EFX_USE_MSI:
	case EFX_CHANNELS:
	case EFX_RXFH_DEFAULT_FLAGS:
	case EFX_DESIGN_PARAM:
	case EFX_PCI_DEVICE:
	case EFX_DEVICE_REVISION:
	case EFX_TIMER_QUANTUM_NS:
		/* These parameters are _get_ only! */
		rc = -EINVAL;
		break;
	case EFX_DRIVER_DATA:
		handle->driver_data = arg->driver_data;
		break;
	case EFX_PARAM_FILTER_BLOCK_KERNEL_UCAST:
		rc = efx_auxbus_filter_set_block(efx,
						 EFX_FILTER_BLOCK_KERNEL_UCAST,
						 arg->b);
		break;
	case EFX_PARAM_FILTER_BLOCK_KERNEL_MCAST:
		rc = efx_auxbus_filter_set_block(efx,
						 EFX_FILTER_BLOCK_KERNEL_MCAST,
						 arg->b);
		break;
	default:
		rc = -EOPNOTSUPP;
		break;
	}

	return rc;
}

static struct efx_auxdev_dl_vi_resources *
efx_auxbus_dl_publish(struct efx_auxdev_client *handle)
{
	struct efx_probe_data *pd;
	struct efx_client *client;
	int rc;

	if (!handle)
		return ERR_PTR(-EINVAL);

	client = container_of(handle, struct efx_client, auxiliary_info);
	if (!client)
		return ERR_PTR(-ENODEV);

	pd = cdev_to_probe_data(handle);
	if (!pd)
		return ERR_PTR(-ENODEV);

	if (client->client_type->vis_allocated)
		return ERR_PTR(-EALREADY);

	rc = efx_net_alloc(&pd->efx);
	if (rc) {
		efx_net_dealloc(&pd->efx);
		return ERR_PTR(rc);
	}

	client->client_type->vis_allocated = true;
	client->vi_resources = (struct efx_auxdev_dl_vi_resources) {
		.vi_base = pd->efx.vi_resources.vi_base,
		.vi_min = pd->efx.vi_resources.vi_min,
		.vi_lim = pd->efx.vi_resources.vi_lim,
		.rss_channel_count = pd->efx.vi_resources.rss_channel_count,
		.vi_shift = pd->efx.vi_resources.vi_shift,
		.vi_stride = pd->efx.vi_resources.vi_stride,
		.mem_bar = pd->efx.vi_resources.mem_bar,
		.pci_dev = pd->efx.pci_dev
	};

	return &client->vi_resources;
}

static void efx_auxbus_dl_unpublish(struct efx_auxdev_client *handle)
{
	struct efx_probe_data *pd;
	struct efx_client *client;

	if (!handle)
		return;

	client = container_of(handle, struct efx_client, auxiliary_info);
	if (!client)
		return;

	pd = cdev_to_probe_data(handle);
	if (!pd)
		return;

	efx_net_dealloc(&pd->efx);
	client->client_type->vis_allocated = false;
}

static int efx_auxbus_vport_new(struct efx_auxdev_client *handle, u16 vlan,
				 bool vlan_restrict)
{
	struct efx_probe_data *pd;

	if (!handle)
		return -EINVAL;

	pd = cdev_to_probe_data(handle);
	if (!pd)
		return -ENODEV;

	return efx_vport_add(&pd->efx, vlan, vlan_restrict);
}

static int efx_auxbus_vport_free(struct efx_auxdev_client *handle, u16 port_id)
{
	struct efx_probe_data *pd;

	if (!handle)
		return -EINVAL;

	pd = cdev_to_probe_data(handle);
	if (!pd)
		return -ENODEV;

	return efx_vport_del(&pd->efx, port_id);
}

static const struct efx_auxdev_ops aux_devops = {
	.open = efx_auxbus_open,
	.close = efx_auxbus_close,
	.fw_rpc = efx_auxbus_fw_rpc,
	.filter_insert = efx_auxbus_filter_insert,
	.filter_remove = efx_auxbus_filter_remove,
	.get_param = efx_auxbus_get_param,
	.set_param = efx_auxbus_set_param,
	.dl_publish = efx_auxbus_dl_publish,
	.dl_unpublish = efx_auxbus_dl_unpublish,
	.vport_new = efx_auxbus_vport_new,
	.vport_free = efx_auxbus_vport_free,
};

int efx_auxbus_send_events(struct efx_probe_data *pd,
			   struct efx_auxdev_event *event)
{
	struct efx_client_type_data *client_type;
	struct efx_auxdev_client *cdev;
	struct efx_client *client;
	enum efx_client_type type;
	unsigned long idx;

	/* Notify all auxiliary bus devices for this function. */
	for (type = 0; type < _EFX_CLIENT_MAX; type++) {
		client_type = pd->client_type[type];
		if (!client_type || !client_type->type_data)
			continue;

		/* Notify open clients that want this event */
		xa_for_each(&client_type->open, idx, client) {
			cdev = &client->auxiliary_info;
			if (!cdev || !cdev->event_handler ||
			    !(cdev->events_requested & BIT(event->type)))
				continue;

			(*cdev->event_handler)(cdev, event);
		}
	}
	return 0;
}

static void efx_auxbus_release(struct device *dev)
{
	struct auxiliary_device *auxdev = to_auxiliary_dev(dev);
	struct efx_auxdev *adev = to_efx_auxdev(auxdev);
	struct sfc_auxdev *sdev;

	ida_free(&efx_auxbus_ida, auxdev->id);
	sdev = container_of(adev, struct sfc_auxdev, auxdev);
	kfree(sdev);
}

static const char *to_auxbus_name(enum efx_client_type type)
{
	/* Not all client types use the auxiliary bus */
	switch (type) {
	case EFX_CLIENT_ONLOAD:
		return EFX_ONLOAD_DEVNAME;
	default:
		return NULL;
	}
}

void efx_auxbus_del_dev(struct efx_client_type_data *client_type)
{
	const char *auxbus_name = to_auxbus_name(client_type->type);
	struct auxiliary_device *auxdev;
	struct sfc_auxdev *sdev;

	/* Not all client types use the auxiliary bus */
	if (!auxbus_name)
		return;
	sdev = client_type->type_data;
	if (!sdev)
		return;

	auxdev = &sdev->auxdev.auxdev;
	auxiliary_device_delete(auxdev);
	auxiliary_device_uninit(auxdev);
	client_type->type_data = NULL;
	/* efx_auxbus_release will be called when all users are gone. */
}

int efx_auxbus_add_dev(struct efx_client_type_data *client_type)
{
	const char *auxbus_name = to_auxbus_name(client_type->type);
	struct auxiliary_device *auxdev;
	struct sfc_auxdev *sdev;
	int rc;

	/* Not all client types use the auxiliary bus */
	if (!auxbus_name)
		return 0;
	/* There is only 1 auxbus exposed for a given function and type. */
	if (client_type->type_data)
		return -EALREADY;

	sdev = kzalloc(sizeof(*sdev), GFP_KERNEL);
	if (!sdev)
		return -ENOMEM;
	auxdev = &sdev->auxdev.auxdev;

	rc = ida_alloc(&efx_auxbus_ida, GFP_KERNEL);
	if (rc < 0)
		goto out_free;
	auxdev->id = rc;

	auxdev->name = auxbus_name;
	auxdev->dev.release = efx_auxbus_release;
	auxdev->dev.parent = &client_type->pd->pci_dev->dev;
	sdev->auxdev.ops = &aux_devops;
	sdev->client_type = client_type;

	rc = auxiliary_device_init(auxdev);
	if (rc)
		goto fail;

	client_type->type_data = sdev;
	rc = auxiliary_device_add(auxdev);
	if (rc) {
		auxiliary_device_uninit(auxdev);
		goto fail;
	}
	return 0;
fail:
	client_type->type_data = NULL;
	ida_free(&efx_auxbus_ida, auxdev->id);
out_free:
	kfree(sdev);
	return rc;
}
