/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2005-2024, Advanced Micro Devices, Inc. */

#include "linux_resource_internal.h"

#include <ci/driver/driverlink_api.h>
#include <ci/driver/ci_ef10.h>

#include "efrm_internal.h"
#include <ci/driver/kernel_compat.h>

#include <linux/rtnetlink.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <net/net_namespace.h>
#include <ci/efrm/efrm_filter.h>
#include <ci/efrm/nic_table.h>
#include <ci/efhw/ef10.h>
#include <ci/efhw/ef100.h>
#include <ci/efhw/nic.h>
#include <ci/tools/sysdep.h>
#include <ci/internal/transport_config_opt.h>
#include "sfcaffinity.h"
#include <ci/driver/resource/linux_efhw_nic.h>
#include <ci/driver/resource/driverlink.h>

#if 0
/* The DL driver and associated calls */
static int efrm_dl_probe(struct efx_dl_device *efrm_dev,
			 const struct net_device *net_dev,
			 const struct efx_dl_device_info *dev_info,
			 const char *silicon_rev);

static void efrm_dl_remove(struct efx_dl_device *efrm_dev);

static void efrm_dl_reset_suspend(struct efx_dl_device *efrm_dev);

static void efrm_dl_reset_resume(struct efx_dl_device *efrm_dev, int ok);

static int efrm_netdev_event(struct notifier_block *this,
			     unsigned long event, void *ptr);

static struct notifier_block efrm_netdev_notifier = {
	.notifier_call = efrm_netdev_event,
};

static int
efrm_dl_event(struct efx_dl_device *efx_dev, void *p_event, int budget);

static struct efx_dl_driver efrm_dl_driver = {
	.name = "resource",
	.priority = EFX_DL_EV_HIGH,
	.flags = EFX_DL_DRIVER_CHECKS_MEDFORD2_VI_STRIDE,
	.probe = efrm_dl_probe,
	.remove = efrm_dl_remove,
	.reset_suspend = efrm_dl_reset_suspend,
	.reset_resume = efrm_dl_reset_resume,
	.handle_event = efrm_dl_event,
};


static inline struct efhw_nic *
efhw_nic_from_netdev(
			const struct net_device *net_dev,
			struct efx_dl_driver *driver)
{
	struct efx_dl_device *dl_dev;
	dl_dev = efx_dl_dev_from_netdev(net_dev, &efrm_dl_driver);
	if (dl_dev && dl_dev->priv)
		return (struct efhw_nic *) dl_dev->priv;
	return NULL;
}

/* Determines whether a known NIC is equivalent to one that would be
 * instantiated according to a [pci_dev] and an [efhw_device_type]. The
 * intended use-case is to check whether a new NIC can step into the shoes of
 * one that went away. */
static inline int
efrm_nic_matches_device(struct efhw_nic* nic, const struct pci_dev* dev,
			const struct efhw_device_type* dev_type)
{
	int match;
	struct pci_dev* nic_dev = efhw_nic_get_pci_dev(nic);
	if (!nic_dev) {
		/* Rediscovery of non-PCI NICs not currently supported */
		return 0;
	}
	match = nic_dev->devfn == dev->devfn && nic_dev->device == dev->device;
	pci_dev_put(nic_dev);
	if (!match)
		return 0;

	/* Check that the PCI device is of the same type and in the same place.
	 */
	if (nic->domain != pci_domain_nr(dev->bus) ||
	    nic->bus_number != dev->bus->number ||
	    nic->devtype.arch != dev_type->arch ||
	    nic->devtype.revision != dev_type->revision ||
	    nic->devtype.variant != dev_type->variant)
		return 0;

	return 1;
}


static inline int
efrm_nic_resources_match(struct efhw_nic* nic,
			 const struct vi_resource_dimensions* res_dim)
{
	int match;
	int old_range, new_range;
	struct efrm_nic* efrm_nic = efrm_nic(nic);

	/* Check that we have a compatible set of available VIs. */
	if (nic->vi_min != res_dim->vi_min ||
	    /* nic->vi_lim might have been reduced owing to a shortage of
	     * IRQs, but that's OK. */
	    nic->vi_lim > res_dim->vi_lim ||
	    nic->vi_stride != res_dim->vi_stride ||
	    efrm_nic->rss_channel_count != res_dim->rss_channel_count)
		return 0;

	/* Check that we have all of the IRQ ranges that we had before. */
	if (nic->vi_irq_n_ranges > res_dim->irq_n_ranges)
		return 0;
	for (old_range = 0; old_range < nic->vi_irq_n_ranges; ++old_range) {
		match = 0;
		for (new_range = 0; new_range < res_dim->irq_n_ranges;
		     ++new_range) {
			if (nic->vi_irq_ranges[old_range].base ==
			    res_dim->irq_ranges[new_range].irq_base &&
			    nic->vi_irq_ranges[old_range].range ==
			    res_dim->irq_ranges[new_range].irq_range) {
				match = 1;
				break;
			}
		}
		if (!match)
			return 0;
	}

	return 1;
}


/* Determines whether the control BAR for the device [dev] is where we expect
 * it to be for the NIC [nic]. This is a requirement for hotplug
 * revivification. */
static inline int
efrm_nic_bar_is_good(struct efhw_nic* nic, struct pci_dev* dev)
{
	return !dev || nic->ctr_ap_addr == pci_resource_start(dev, nic->ctr_ap_bar);
}


static struct linux_efhw_nic*
efrm_get_rediscovered_nic(struct pci_dev* dev,
			  const struct efhw_device_type* dev_type,
			  const struct vi_resource_dimensions* res_dim)
{
	struct linux_efhw_nic* lnic = NULL;
	struct efhw_nic* old_nic;
	int nic_index;

	/* We can't detect hotplug without the pci information to compare */
	if( !dev )
		return NULL;

	spin_lock_bh(&efrm_nic_tablep->lock);
	EFRM_FOR_EACH_NIC(nic_index, old_nic) {
		/* We would like to break out of this loop after rediscovering
		 * a NIC, but the EFRM_FOR_EACH_NIC construct doesn't allow
		 * this, so instead we check explicitly that we haven't set
		 * [lnic] yet. */
		if (lnic == NULL && old_nic != NULL &&
			efrm_nic_matches_device(old_nic, dev, dev_type)) {
			EFRM_ASSERT(old_nic->resetting);
			if (!efrm_nic_bar_is_good(old_nic, dev)) {
				EFRM_WARN("%s: New device matches nic_index %d "
					  "but has different BAR. Existing "
					  "Onload stacks will not use the new "
					  "device.",
					  __func__, nic_index);
			}
			else if (!efrm_nic_resources_match(old_nic, res_dim)) {
				EFRM_WARN("%s: New device matches nic_index %d "
					  "but has different resource "
					  "parameters. Existing Onload stacks "
					  "will not use the new device.",
					  __func__, nic_index);
			}
			else {
				EFRM_NOTICE("%s: Rediscovered nic_index %d",
					    __func__, nic_index);
				lnic = linux_efhw_nic(old_nic);
			}
		}
	}
	spin_unlock_bh(&efrm_nic_tablep->lock);
	/* We can drop the lock now as [lnic] will not go away until the module
	 * unloads. */

	return lnic;
}
#endif


static int init_resource_info(struct efx_auxdev *edev,
                              struct efx_auxdev_client *client,
                              struct efx_auxdev_dl_vi_resources *vi_res,
                              struct vi_resource_dimensions *rd,
                              struct pci_dev **pci_dev,
                              unsigned int *tq)
{
  union efx_auxiliary_param_value val;
  int rc;

  *pci_dev = vi_res->pci_dev;
  /* FIXME SCJ pci_dev handling */
  rd->pci_dev = *pci_dev;

  /* FIXME SCJ how does cleanup work, do we need to call dl_unpublish? */
  rc = edev->ops->get_param(client, EFX_MEMBASE, &val);
  if( rc < 0 )
    return rc;

  rc = edev->ops->get_param(client, EFX_TIMER_QUANTUM_NS, &val);
  if( rc < 0 )
    return rc;
  *tq = val.value;

  rd->vi_min = vi_res->vi_min;
  rd->vi_lim = vi_res->vi_lim;
  /* FIXME SCJ confirm that rx_channel_count is the right value */
  rd->rss_channel_count = vi_res->rss_channel_count;
  rd->vi_base = vi_res->vi_base;
  rd->vi_shift = vi_res->vi_shift;
  rd->vi_stride = vi_res->vi_stride;
  rd->mem_bar = vi_res->mem_bar;

  /* assume all the register STEPS are identical */
  EFRM_BUILD_ASSERT(ER_DZ_EVQ_RPTR_REG_STEP == ER_DZ_EVQ_TMR_REG_STEP);
  EFRM_BUILD_ASSERT(ER_DZ_EVQ_RPTR_REG_STEP == ER_DZ_RX_DESC_UPD_REG_STEP);
  EFRM_BUILD_ASSERT(ER_DZ_EVQ_RPTR_REG_STEP == ER_DZ_TX_DESC_UPD_REG_STEP);

  EFRM_TRACE("Using VI range %d+(%d-%d)<<%d bar %d ws 0x%x", rd->vi_base,
             rd->vi_min, rd->vi_lim, rd->vi_shift, rd->mem_bar, rd->vi_stride);

  /* The net driver manages our interrupts for ef10. */
  rd->irq_n_ranges = 0;
  rd->irq_prime_reg = NULL;

  rd->efhw_ops = &ef10aux_char_functional_units;

  return 0;
}


static struct linux_efhw_nic*
efrm_get_rediscovered_nic(struct pci_dev* dev,
                          const struct efhw_device_type* dev_type,
                          const struct vi_resource_dimensions* res_dim)
{
  /* FIXME SCJ consider hotplug */
  return NULL;
}


/* FIXME API driver data token? Return budget consumed? Can we have the dev here? */
static void ef10_handler(struct efx_auxdev_client *client,
                         const struct efx_auxdev_event *event)
{
  EFRM_TRACE("%s: %s", __func__, dev_name(&client->auxdev->auxdev.dev));
}

static int ef10_probe(struct auxiliary_device *auxdev,
                      const struct auxiliary_device_id *id)
{
  struct efx_auxdev *edev = to_efx_auxdev(auxdev);
  struct efx_auxdev_dl_vi_resources *vi_res;
  struct vi_resource_dimensions res_dim;
  struct efx_auxdev_client *client;
  union efx_auxiliary_param_value val;
  struct efhw_device_type dev_type;
  unsigned timer_quantum_ns;
  struct linux_efhw_nic *lnic;
  struct efhw_nic *nic;
  struct net_device *net_dev;
  struct pci_dev *pci_dev;
  int rc;

  client = edev->ops->open(auxdev, &ef10_handler, EFX_AUXDEV_ALL_EVENTS);

  EFRM_NOTICE("%s name %s", __func__, id->name);

  if( IS_ERR(client) ) {
    rc = PTR_ERR(client);
    goto fail1;
  }

  rtnl_lock();
  vi_res = edev->ops->dl_publish(client);
  rtnl_unlock();
  if( IS_ERR(vi_res) ) {
    rc = PTR_ERR(vi_res);
    goto fail2;
  }

  rc = edev->ops->get_param(client, EFX_NETDEV, &val);
  if( rc < 0 )
    goto fail3;
  net_dev = val.net_dev;

  rc = init_resource_info(edev, client, vi_res, &res_dim, &pci_dev,
                          &timer_quantum_ns);
  if( rc < 0 )
    goto fail3;

  rc = efhw_sfc_device_type_init(&dev_type, pci_dev);
  if( rc < 0 ) {
    EFRM_ERR("%s: efhw_device_type_init failed %04x:%04x rc %d",
    __func__, (unsigned) pci_dev->vendor,
    (unsigned) pci_dev->device, rc);
    goto fail3;
  }

  EFRM_NOTICE("%s pci_dev=%04x:%04x(%d) type=%d:%c%d ifindex=%d",
              pci_name(pci_dev) ?  pci_name(pci_dev) : "?",
              (unsigned) pci_dev->vendor,
              (unsigned) pci_dev->device, dev_type.revision,
              dev_type.arch, dev_type.variant, dev_type.revision,
              net_dev->ifindex);

  lnic = efrm_get_rediscovered_nic(pci_dev, &dev_type, &res_dim);

  rtnl_lock();
  /* FIXME SCJ check probe flags - do we need this */
  rc = efrm_nic_add(client, &auxdev->dev, &dev_type, 0,
                    (/*no const*/ struct net_device *)net_dev, &lnic, &res_dim,
                    timer_quantum_ns);
  if( rc < 0 ) {
    rtnl_unlock();
    goto fail3;
  }

#if 0
  efrm_nic_add_sysfs(net_dev, &efrm_dev->pci_dev->dev);
#endif

  /* FIXME SCJ dl stores pointer for dl_dev_info here */
  nic = &lnic->efrm_nic.efhw_nic;
  nic->mtu = net_dev->mtu + ETH_HLEN; /* ? + ETH_VLAN_HLEN */
  nic->rss_channel_count = res_dim.rss_channel_count;
  /* FIXME SCJ work out the best way to deal with having both aux and pci dev */
  nic->pci_dev = pci_dev;

  val.driver_data = nic;
  rc = edev->ops->set_param(client, EFX_DRIVER_DATA, &val);
  /* FIXME SCJ check this failure path */
  if( rc < 0 ) {
    rtnl_unlock();
    goto fail4;
  }

  efrm_notify_nic_probe(nic, net_dev);
  rtnl_unlock();
  return 0;

 fail4:
  efrm_nic_unplug(nic);
 fail3:
  edev->ops->dl_unpublish(client);
 fail2:
  edev->ops->close(client);
 fail1:
  return rc;
}

/* When we unregister ourselves on module removal, this function will be
 * called for all the devices we claimed. It will also be called on a single
 * device if that device is unplugged.
 */
void ef10_remove(struct auxiliary_device *auxdev)
{
  struct efx_auxdev *edev = to_efx_auxdev(auxdev);
  struct efx_auxdev_client *client;
  struct linux_efhw_nic *lnic;
  struct efhw_nic *nic;

  EFRM_TRACE("%s: %s", __func__, dev_name(&auxdev->dev));

  nic = efhw_nic_find_by_dev(&auxdev->dev);
  if( !nic )
    return;

#if 0
  efrm_nic_del_sysfs(&efrm_dev->pci_dev->dev);
#endif
  lnic = linux_efhw_nic(nic);
  client = (struct efx_auxdev_client*)lnic->drv_device;
  if( !client )
    return;

  efrm_notify_nic_remove(nic);

  /* flush all outstanding dma queues */
  efrm_nic_flush_all_queues(nic, 0);

  lnic->drv_device = NULL;
#if 0
  lnic->efrm_nic.dl_dev_info = NULL;
#endif

  /* Wait for all in-flight driverlink calls to finish.  Since we
   * have already cleared [lnic->drv_device], no new calls can
   * start. */
  efhw_nic_flush_drv(nic);
  efrm_nic_unplug(nic);

  /* Absent hardware is treated as a protracted reset. */
  efrm_nic_reset_suspend(nic);
  ci_atomic32_or(&nic->resetting, NIC_RESETTING_FLAG_UNPLUGGED);

  edev->ops->dl_unpublish(client);
  edev->ops->close(client);
}

#if 0
static void efrm_dl_reset_suspend(struct efx_dl_device *efrm_dev)
{
	struct efhw_nic *nic = efrm_dev->priv;

	if (!nic)
		return;

	EFRM_NOTICE("%s:", __func__);

	efrm_nic_reset_suspend(nic);

	ci_atomic32_or(&nic->resetting, NIC_RESETTING_FLAG_RESET);
}

static void efrm_dl_reset_resume(struct efx_dl_device *efrm_dev, int ok)
{
	struct efhw_nic *nic = efrm_dev->priv;
	struct efrm_nic *efrm_nic;

	if (!nic)
		return;

	efrm_nic = efrm_nic(nic);

	EFRM_NOTICE("%s: ok=%d", __func__, ok);

	/* Driverlink calls might have been disabled forcibly if, e.g., the NIC
	 * had been in BIST mode.  We know that they're safe now, so enable
	 * them. */
	efrm_driverlink_resume(nic);

	/* VI base may have changed on EF10 and EF100 hardware */
	if (nic->devtype.arch == EFHW_ARCH_EF10 ||
	    nic->devtype.arch == EFHW_ARCH_EF100) {
		struct efx_dl_ef10_resources *ef10_res = NULL;
		efx_dl_search_device_info(efrm_nic->dl_dev_info, 
					  EFX_DL_EF10_RESOURCES,
					  struct efx_dl_ef10_resources,
					  hdr, ef10_res);
		/* We shouldn't be able to get here if there wasn't an
		 * ef10_res structure as we know it's an EF10 NIC
		 */
		EFRM_ASSERT(ef10_res != NULL);
		if( nic->vi_base != ef10_res->vi_base ) {
			EFRM_TRACE("%s: vi_base changed from %d to %d\n",
				   __FUNCTION__, nic->vi_base, 
				   ef10_res->vi_base);
			nic->vi_base = ef10_res->vi_base;
		}
		if( nic->vi_shift != ef10_res->vi_shift ) {
			EFRM_TRACE("%s: vi_shift changed from %d to %d\n",
				   __FUNCTION__, nic->vi_shift, 
				   ef10_res->vi_shift);
			nic->vi_shift = ef10_res->vi_shift;
		}
		if( nic->ctr_ap_bar != ef10_res->mem_bar ) {
			EFRM_TRACE("%s: mem_bar changed from %d to %d\n",
				   __FUNCTION__, nic->ctr_ap_bar,
				   ef10_res->mem_bar);
			nic->ctr_ap_bar = ef10_res->mem_bar;
		}
		if( nic->vi_stride != ef10_res->vi_stride ) {
			EFRM_TRACE("%s: vi_stride changed from %d to %d\n",
				   __FUNCTION__, nic->vi_stride,
				   ef10_res->vi_stride);
			nic->vi_stride = ef10_res->vi_stride;
		}
	}

	/* Remove record on que initialization from before a reset
	 * No hardware operation will be performed */
	efrm_nic_flush_all_queues(nic, EFRM_FLUSH_QUEUES_F_NOHW |
	                               EFRM_FLUSH_QUEUES_F_INJECT_EV);

        if( ok )
          nic->resetting = 0;
        
        efhw_nic_post_reset(nic);

	efrm_nic_post_reset(nic);
}

int efrm_driverlink_register(void)
{
	int rc;

	EFRM_TRACE("%s:", __func__);

	rc = efx_dl_register_driver(&efrm_dl_driver);
	if (rc)
		return rc;

	rc = register_netdevice_notifier(&efrm_netdev_notifier);
	if (rc) {
		efx_dl_unregister_driver(&efrm_dl_driver);
		return rc;
	}

	return 0;
}

void efrm_driverlink_unregister(void)
{
	EFRM_TRACE("%s:", __func__);

	unregister_netdevice_notifier(&efrm_netdev_notifier);
	efx_dl_unregister_driver(&efrm_dl_driver);
}


/* In the ordinary course of things, when hardware is unplugged, the kernel
 * will tell the net driver, which will forward the news to us by calling our
 * removal hook, and this will prevent us from attempting any further
 * driverlink calls on that device. However, if we detect that hardware has
 * gone before receiving the notification, we would like just the same to
 * prevent further driverlink activity. These functions allow us to arrange
 * that. */

/* [failure_generation] is the value returned by efrm_driverlink_generation()
 * at some point before the detected failure that prompted this call. */
void efrm_driverlink_desist(struct efhw_nic* nic, unsigned failure_generation)
{
	struct efrm_nic *rnic = efrm_nic(nic);
	EFRM_TRACE("%s:", __func__);

	spin_lock_bh(&rnic->lock);
	if (failure_generation == rnic->driverlink_generation)
		rnic->rnic_flags |= EFRM_NIC_FLAG_DRIVERLINK_PROHIBITED;
	spin_unlock_bh(&rnic->lock);
}

void efrm_driverlink_resume(struct efhw_nic* nic)
{
	struct efrm_nic *rnic = efrm_nic(nic);
	EFRM_TRACE("%s:", __func__);

	spin_lock_bh(&rnic->lock);
	++rnic->driverlink_generation;
	rnic->rnic_flags &= ~EFRM_NIC_FLAG_DRIVERLINK_PROHIBITED;
	spin_unlock_bh(&rnic->lock);
}

unsigned efrm_driverlink_generation(struct efhw_nic* nic)
{
	struct efrm_nic *rnic = efrm_nic(nic);
	return READ_ONCE(rnic->driverlink_generation);
}


static int efrm_netdev_event(struct notifier_block *this,
			     unsigned long event, void *ptr)
{
	struct net_device *net_dev = netdev_notifier_info_to_dev(ptr);
	struct efhw_nic *nic;

	if (event == NETDEV_CHANGEMTU) {
		nic = efhw_nic_from_netdev(net_dev, &efrm_dl_driver);
		if (nic) {
			EFRM_TRACE("%s: old=%d new=%d", __func__,
				   nic->mtu, net_dev->mtu + ETH_HLEN);
			nic->mtu = net_dev->mtu + ETH_HLEN; /* ? + ETH_VLAN_HLEN */
		}
	}
	if (event == NETDEV_CHANGENAME) {
		nic = efhw_nic_from_netdev(net_dev, &efrm_dl_driver);
		if (nic) {
			efrm_filter_rename(nic, net_dev);
		}
	}

	return NOTIFY_DONE;
}


static int
efrm_dl_event(struct efx_dl_device *efx_dev, void *p_event, int budget)
{
	struct efhw_nic *nic;
	efhw_event_t *ev = p_event;
	int rc;

	if (! (efx_dev && efx_dev->priv) )
		/* this device has not been registered via driverlink ... perhaps AF_XDP */
		return 0;

	nic = efx_dev->priv;
	rc = efhw_nic_handle_event(nic, ev, budget);
	return rc;
}
#endif


static const struct auxiliary_device_id ef10_id_table[] = {
  { .name = "sfc." EFX_ONLOAD_DEVNAME, },
  {},
};
MODULE_DEVICE_TABLE(auxiliary, ef10_id_table);


struct auxiliary_driver ef10_drv = {
  .name = "ef10",
  .probe = ef10_probe,
  .remove = ef10_remove,
  .id_table = ef10_id_table,
};

