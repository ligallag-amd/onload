/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2018 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "ef100_nic.h"
#include <linux/module.h>
//#include <linux/netdevice.h>
#include "efx_common.h"
#include "efx_channels.h"
#include "io.h"
#include "debugfs.h"
#include "selftest.h"
#include "ef100_regs.h"
#include "mcdi.h"
#include "mcdi_pcol.h"
#include "mcdi_port_common.h"
#include "mcdi_functions.h"
#include "mcdi_filters.h"
#include "ef100.h"
#include "ef100_rx.h"
#include "ef100_tx.h"
#include "ef100_sriov.h"
#include "ef100_rep.h"
#include "ef100_netdev.h"
#include "tc.h"
#include "mae.h"
#include "xdp.h"
#include "rx_common.h"
#ifdef CONFIG_SFC_VDPA
#include "ef100_vdpa.h"
#endif

#define EF100_MAX_VIS 4096
#define EF100_NUM_MCDI_BUFFERS	1

#ifndef EF100_RESET_PORT
#define EF100_RESET_PORT ((ETH_RESET_MAC | ETH_RESET_PHY) << ETH_RESET_SHARED_SHIFT)
#endif

static bool ef100_has_dynamic_sensors(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;

	return efx_ef100_has_cap(nic_data->datapath_caps2, DYNAMIC_SENSORS);
}

/*	MCDI
 */
static u8 *ef100_mcdi_buf(struct efx_nic *efx, u8 bufid,
			      dma_addr_t *dma_addr)
{
	struct ef100_nic_data *nic_data = efx->nic_data;

	if (dma_addr)
		*dma_addr = nic_data->mcdi_buf.dma_addr +
			    bufid * ALIGN(MCDI_BUF_LEN, 256);
	return nic_data->mcdi_buf.addr + bufid * ALIGN(MCDI_BUF_LEN, 256);
}

static int ef100_get_warm_boot_count(struct efx_nic *efx)
{
	efx_dword_t reg;

	efx_readd(efx, &reg, efx_reg(efx, ER_GZ_MC_SFT_STATUS));

	if (EFX_DWORD_FIELD(reg, EFX_DWORD_0) == 0xffffffff) {
		netif_err(efx, hw, efx->net_dev, "Hardware unavailable\n");
		efx->state = STATE_DISABLED;
		return -ENETDOWN;
	} else {
		return EFX_DWORD_FIELD(reg, EFX_WORD_1) == 0xb007 ?
			EFX_DWORD_FIELD(reg, EFX_WORD_0) : -EIO;
	}
}

static void ef100_mcdi_request(struct efx_nic *efx, u8 bufid,
				   const efx_dword_t *hdr, size_t hdr_len,
				   const efx_dword_t *sdu, size_t sdu_len)
{
	dma_addr_t dma_addr;
	u8 *pdu = ef100_mcdi_buf(efx, bufid, &dma_addr);

	memcpy(pdu, hdr, hdr_len);
	memcpy(pdu + hdr_len, sdu, sdu_len);
	wmb();

	/* The hardware provides 'low' and 'high' (doorbell) registers
	 * for passing the 64-bit address of an MCDI request to
	 * firmware.  However the dwords are swapped by firmware.  The
	 * least significant bits of the doorbell are then 0 for all
	 * MCDI requests due to alignment.
	 */
	_efx_writed(efx, cpu_to_le32((u64)dma_addr >> 32),  efx_reg(efx, ER_GZ_MC_DB_LWRD));
	_efx_writed(efx, cpu_to_le32((u32)dma_addr),  efx_reg(efx, ER_GZ_MC_DB_HWRD));
}

static bool ef100_mcdi_poll_response(struct efx_nic *efx, u8 bufid)
{
	const efx_dword_t hdr =
		*(const efx_dword_t *)(ef100_mcdi_buf(efx, bufid, NULL));

	rmb();
	return EFX_DWORD_FIELD(hdr, MCDI_HEADER_RESPONSE);
}

static void
ef100_mcdi_read_response(struct efx_nic *efx, u8 bufid,
			     efx_dword_t *outbuf, size_t offset, size_t outlen)
{
	const u8 *pdu = ef100_mcdi_buf(efx, bufid, NULL);

	memcpy(outbuf, pdu + offset, outlen);
}

static int ef100_mcdi_poll_reboot(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	int rc;

	rc = ef100_get_warm_boot_count(efx);
	if (rc < 0) {
		/* The firmware is presumably in the process of
		 * rebooting.  However, we are supposed to report each
		 * reboot just once, so we must only do that once we
		 * can read and store the updated warm boot count.
		 */
		return 0;
	}

	if (rc == nic_data->warm_boot_count)
		return 0;

	nic_data->warm_boot_count = rc;

	return -EIO;
}

static void ef100_mcdi_reboot_detected(struct efx_nic *efx)
{
	efx->last_reset = jiffies;
}

/* Get an MCDI buffer
 *
 * The caller is responsible for preventing racing by holding the
 * MCDI iface_lock.
 */
static bool ef100_mcdi_get_buf(struct efx_nic *efx, u8 *bufid)
{
	struct ef100_nic_data *nic_data = efx->nic_data;

	*bufid = ffz(nic_data->mcdi_buf_use);
	if (*bufid < EF100_NUM_MCDI_BUFFERS) {
		set_bit(*bufid, &nic_data->mcdi_buf_use);
		return true;
	}

	return false;
}

/* Return an MCDI buffer */
static void ef100_mcdi_put_buf(struct efx_nic *efx, u8 bufid)
{
	struct ef100_nic_data *nic_data = efx->nic_data;

	EFX_WARN_ON_PARANOID(bufid >= EF100_NUM_MCDI_BUFFERS);
	EFX_WARN_ON_PARANOID(!test_bit(bufid, &nic_data->mcdi_buf_use));

	clear_bit(bufid, &nic_data->mcdi_buf_use);
}

/*	MCDI calls
 */
int ef100_get_mac_address(struct efx_nic *efx, u8 *mac_address,
			  int client_handle, bool empty_ok)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_CLIENT_MAC_ADDRESSES_OUT_LEN(1));
	MCDI_DECLARE_BUF(inbuf, MC_CMD_GET_CLIENT_MAC_ADDRESSES_IN_LEN);
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, GET_CLIENT_MAC_ADDRESSES_IN_CLIENT_HANDLE,
		       client_handle);

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_CLIENT_MAC_ADDRESSES, inbuf,
			  sizeof(inbuf), outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;

	if (outlen >= MC_CMD_GET_CLIENT_MAC_ADDRESSES_OUT_LEN(1)) {
		ether_addr_copy(mac_address, MCDI_PTR(outbuf,
				GET_CLIENT_MAC_ADDRESSES_OUT_MAC_ADDRS));
	} else if (empty_ok) {
		pci_warn(efx->pci_dev,
			 "No MAC address provisioned for client ID %#x.\n",
			 client_handle);
		eth_zero_addr(mac_address);
	} else {
		return -ENOENT;
	}
	return 0;
}

int efx_ef100_init_datapath_caps(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_CAPABILITIES_V10_OUT_LEN);
	struct ef100_nic_data *nic_data = efx->nic_data;
	u8 vi_window_mode;
	size_t outlen;
	int rc;

	BUILD_BUG_ON(MC_CMD_GET_CAPABILITIES_IN_LEN != 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_CAPABILITIES, NULL, 0,
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < MC_CMD_GET_CAPABILITIES_V4_OUT_LEN) {
		netif_err(efx, drv, efx->net_dev,
			  "unable to read datapath firmware capabilities\n");
		return -EIO;
	}

	nic_data->datapath_caps = MCDI_DWORD(outbuf,
					     GET_CAPABILITIES_OUT_FLAGS1);
	nic_data->datapath_caps2 = MCDI_DWORD(outbuf,
					      GET_CAPABILITIES_V2_OUT_FLAGS2);

	vi_window_mode = MCDI_BYTE(outbuf,
				   GET_CAPABILITIES_V3_OUT_VI_WINDOW_MODE);
	rc = efx_mcdi_window_mode_to_stride(efx, vi_window_mode);
	if (rc)
		return rc;

	if (efx_ef100_has_cap(nic_data->datapath_caps2, TX_TSO_V3)) {
		struct net_device *net_dev = efx->net_dev;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_HW_ENC_FEATURES)
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_GSO_PARTIAL)
		netdev_features_t tso = NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_GSO_PARTIAL |
					NETIF_F_GSO_UDP_TUNNEL | NETIF_F_GSO_UDP_TUNNEL_CSUM |
					NETIF_F_GSO_GRE | NETIF_F_GSO_GRE_CSUM;

		net_dev->features |= tso;
		efx_add_hw_features(efx, tso);
		net_dev->hw_enc_features |= tso;
		/* EF100 HW can only offload outer checksums if they are UDP,
		 * so for GRE_CSUM we have to use GSO_PARTIAL.
		 */
		net_dev->gso_partial_features |= NETIF_F_GSO_GRE_CSUM;
#else
		netdev_features_t tso = NETIF_F_TSO | NETIF_F_TSO6 |
					NETIF_F_GSO_UDP_TUNNEL | NETIF_F_GSO_UDP_TUNNEL_CSUM |
					NETIF_F_GSO_GRE;

		net_dev->features |= tso;
		efx_add_hw_features(efx, tso);
		net_dev->hw_enc_features |= tso;
#endif
#else
		netdev_features_t tso = NETIF_F_TSO | NETIF_F_TSO6;

		net_dev->features |= tso;
		efx_add_hw_features(efx, tso);
#endif
	}
	efx->num_mac_stats = MCDI_WORD(outbuf,
				   GET_CAPABILITIES_V4_OUT_MAC_STATS_NUM_STATS);
	if (outlen >= MC_CMD_GET_CAPABILITIES_V10_OUT_LEN) {
		efx->supported_bitmap =
			MCDI_DWORD(outbuf,
				   GET_CAPABILITIES_V10_OUT_SUPPORTED_QUEUE_SIZES);
		efx->guaranteed_bitmap =
			MCDI_DWORD(outbuf,
				   GET_CAPABILITIES_V10_OUT_GUARANTEED_QUEUE_SIZES);
	}
	netif_dbg(efx, probe, efx->net_dev,
		  "firmware reports num_mac_stats = %u\n",
		  efx->num_mac_stats);
	return 0;
}

int ef100_alloc_qdma_buffer(struct efx_nic *efx, struct efx_buffer *buffer,
			    unsigned int len)
{
	int rc = efx_nic_alloc_buffer(efx, buffer, len, GFP_KERNEL);

	if (rc)
		return rc;

	return ef100_regionmap_buffer(efx, &buffer->dma_addr);
}

/*	Event handling
 */
static int ef100_ev_probe(struct efx_channel *channel)
{
	/* Allocate an extra descriptor for the QMDA status completion entry */
	return ef100_alloc_qdma_buffer(channel->efx, &channel->eventq,
				       (channel->eventq_mask + 2) *
				       sizeof(efx_qword_t));
}

static int ef100_ev_init(struct efx_channel *channel)
{
	struct ef100_nic_data *nic_data = channel->efx->nic_data;

	/* initial phase is 0 */
	clear_bit(channel->channel, nic_data->evq_phases);

	return efx_mcdi_ev_init(channel, false, false);
}

static void ef100_ev_read_ack(struct efx_channel *channel)
{
	efx_dword_t evq_prime;

	EFX_POPULATE_DWORD_2(evq_prime,
			     ERF_GZ_EVQ_ID, channel->channel,
			     ERF_GZ_IDX, channel->eventq_read_ptr &
					 channel->eventq_mask);

	efx_writed(channel->efx, &evq_prime,
		   efx_reg(channel->efx, ER_GZ_EVQ_INT_PRIME));

#ifdef EFX_NOT_UPSTREAM
#ifdef SFC_NAPI_DEBUG
	channel->last_irq_reprime_jiffies = jiffies;
#endif
#endif
}

static bool ef100_ev_mcdi_pending(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;
	struct ef100_nic_data *nic_data;
	unsigned int read_ptr;
	efx_qword_t *p_event;
	bool evq_phase;
	bool ev_phase;
	int ev_type;

	if (unlikely(!channel->enabled))
		return false;

	nic_data = efx->nic_data;
	evq_phase = test_bit(channel->channel, nic_data->evq_phases);
	read_ptr = channel->eventq_read_ptr;

	for (;;) {
		p_event = efx_event(channel, read_ptr++);
		ev_phase = !!EFX_QWORD_FIELD(*p_event, ESF_GZ_EV_RXPKTS_PHASE);
		if (ev_phase != evq_phase)
			return false;

		ev_type = EFX_QWORD_FIELD(*p_event, ESF_GZ_E_TYPE);
		if (ev_type == ESE_GZ_EF100_EV_MCDI)
			return true;
	}
}

static int ef100_ev_mcdi(struct efx_channel *channel,
			 efx_qword_t *p_event, int quota)
{
	int rc = 0, spent = 0;

	if (!efx_mcdi_process_event(channel, p_event) &&
	    !efx_mcdi_port_process_event_common(channel, p_event,
						&rc, quota)) {
		int code = EFX_QWORD_FIELD(*p_event, MCDI_EVENT_CODE);
		struct efx_nic *efx = channel->efx;

		if (code == MCDI_EVENT_CODE_DYNAMIC_SENSORS_STATE_CHANGE ||
		    code == MCDI_EVENT_CODE_DYNAMIC_SENSORS_CHANGE)
			efx_mcdi_dynamic_sensor_event(efx, p_event);
		else
			netif_info(efx, drv, efx->net_dev,
			   "Unhandled MCDI event " EFX_QWORD_FMT " code %d\n",
			   EFX_QWORD_VAL(*p_event), code);
	}
	if (rc > 0)
		spent += rc;
	else if (rc < 0)
		spent++;
	return spent;
}

static void efx_ef100_handle_driver_generated_event(struct efx_channel *channel,
						    efx_qword_t *event)
{
	struct efx_nic *efx = channel->efx;
	struct efx_rx_queue *rx_queue;
	u32 subcode;

	subcode = EFX_QWORD_FIELD(*event, EFX_DWORD_0);

	switch (EFX_EF100_DRVGEN_CODE(subcode)) {
	case EFX_EF100_TEST:
		netif_info(efx, drv, efx->net_dev,
			   "Driver initiated event " EFX_QWORD_FMT "\n",
			   EFX_QWORD_VAL(*event));
		break;
	case EFX_EF100_REFILL:
		/* The queue must be empty, so we won't receive any rx
		 * events, so efx_process_channel() won't refill the
		 * queue. Refill it here
		 */
		efx_for_each_channel_rx_queue(rx_queue, channel)
			if (EFX_EF100_DRVGEN_DATA(subcode) ==
			    efx_rx_queue_index(rx_queue))
				efx_fast_push_rx_descriptors(rx_queue, true);
		break;
	default:
		netif_err(efx, hw, efx->net_dev,
			  "channel %d unknown driver event type %u"
			  " (data " EFX_QWORD_FMT ")\n",
			  channel->channel, (unsigned int) subcode,
			  EFX_QWORD_VAL(*event));
	}
}

static int ef100_ev_process(struct efx_channel *channel, int quota)
{
	struct efx_nic *efx = channel->efx;
	struct ef100_nic_data *nic_data;
	bool evq_phase, old_evq_phase;
	unsigned int read_ptr;
	efx_qword_t *p_event;
	int spent = 0;
	bool ev_phase;
	int ev_type;

	if (unlikely(!channel->enabled))
		return 0;

	nic_data = efx->nic_data;
	evq_phase = test_bit(channel->channel, nic_data->evq_phases);
	old_evq_phase = evq_phase;
	read_ptr = channel->eventq_read_ptr;
	BUILD_BUG_ON(ESF_GZ_EV_RXPKTS_PHASE_LBN != ESF_GZ_EV_TXCMPL_PHASE_LBN);

	while (spent < quota) {
		p_event = efx_event(channel, read_ptr);

		ev_phase = !!EFX_QWORD_FIELD(*p_event, ESF_GZ_EV_RXPKTS_PHASE);
		if (ev_phase != evq_phase)
			break;

		netif_vdbg(efx, drv, efx->net_dev,
			   "processing event on %d " EFX_QWORD_FMT "\n",
			   channel->channel, EFX_QWORD_VAL(*p_event));

		ev_type = EFX_QWORD_FIELD(*p_event, ESF_GZ_E_TYPE);

		switch (ev_type) {
		case ESE_GZ_EF100_EV_RX_PKTS:
			spent += efx_ef100_ev_rx(channel, p_event);
			break;
		case ESE_GZ_EF100_EV_MCDI:
			spent += ef100_ev_mcdi(channel, p_event,
					       quota - spent);
			break;
		case ESE_GZ_EF100_EV_TX_COMPLETION:
			ef100_ev_tx(channel, p_event);
			break;
		case ESE_GZ_EF100_EV_DRIVER:
			efx_ef100_handle_driver_generated_event(channel,
								p_event);
			break;
		default:
			netif_info(efx, drv, efx->net_dev,
				   "Unhandled event " EFX_QWORD_FMT "\n",
				   EFX_QWORD_VAL(*p_event));
		}

		++read_ptr;
		if ((read_ptr & channel->eventq_mask) == 0)
			evq_phase = !evq_phase;

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_BUSYPOLL)
		if (efx->interrupt_mode == EFX_INT_MODE_POLLED)
			if ((read_ptr % 512) == 0) {
				/* Poke EVQ_INT_PRIME once in a while */
				channel->eventq_read_ptr = read_ptr;
				ef100_ev_read_ack(channel);
			}
#endif
	}

	channel->eventq_read_ptr = read_ptr;
	if (evq_phase != old_evq_phase)
		change_bit(channel->channel, nic_data->evq_phases);

#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_BUSYPOLL)
	if (efx->interrupt_mode == EFX_INT_MODE_POLLED)
		/* always return quota so we're immediately rescheduled. */
		spent = quota;
#endif

	if (spent > quota)
		return quota;

	return spent;
}

static irqreturn_t ef100_msi_interrupt(int irq, void *dev_id)
{
	struct efx_msi_context *context = dev_id;
	struct efx_nic *efx = context->efx;
	struct efx_channel *channel;

	channel = efx_get_channel(efx, context->index);
	netif_vdbg(efx, intr, efx->net_dev,
		   "IRQ %d on CPU %d\n", irq, raw_smp_processor_id());

#ifdef EFX_NOT_UPSTREAM
#ifdef SFC_NAPI_DEBUG
	channel->last_irq_jiffies = jiffies;
#endif
#endif

	if (likely(READ_ONCE(efx->irq_soft_enabled))) {
		/* Note test interrupts */
		if (context->index == efx->irq_level)
			efx->last_irq_cpu = raw_smp_processor_id();

		/* Schedule processing of the channel */
		efx_schedule_channel_irq(channel);
	}

	return IRQ_HANDLED;
}

int ef100_phy_probe(struct efx_nic *efx)
{
	struct efx_mcdi_phy_data *phy_data;
	int rc;

	/* Probe for the PHY */
	efx->phy_data = kzalloc(sizeof(struct efx_mcdi_phy_data), GFP_KERNEL);
	if (efx->phy_data == NULL)
		return -ENOMEM;

	rc = efx_mcdi_get_phy_cfg(efx, efx->phy_data);
	if (rc)
		return rc;

	/* Populate driver and ethtool settings */
	phy_data = efx->phy_data;
	mcdi_to_ethtool_linkset(efx, phy_data->media, phy_data->supported_cap,
				efx->link_advertising);
	efx->fec_config = mcdi_fec_caps_to_ethtool(phy_data->supported_cap,
						   false);

	/* Default to Autonegotiated flow control if the PHY supports it */
	efx->wanted_fc = EFX_FC_RX | EFX_FC_TX;
	if (phy_data->supported_cap & (1 << MC_CMD_PHY_CAP_AN_LBN))
		efx->wanted_fc |= EFX_FC_AUTO;
	efx_link_set_wanted_fc(efx, efx->wanted_fc);

	/* Push settings to the PHY. Failure is not fatal, the user can try to
	 * fix it using ethtool.
	 */
	rc = efx_mcdi_port_reconfigure(efx);
	if (rc && rc != -EPERM)
		netif_warn(efx, drv, efx->net_dev,
			   "could not initialise PHY settings\n");

	return 0;
}

int ef100_filter_table_probe(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	bool rss_limited, additional_rss;

	rss_limited = efx_ef100_has_cap(nic_data->datapath_caps,
					RX_RSS_LIMITED);
	additional_rss = efx_ef100_has_cap(nic_data->datapath_caps,
					   ADDITIONAL_RSS_MODES);

	return efx_mcdi_filter_table_probe(efx, rss_limited,
					   additional_rss);
}

static int ef100_filter_table_init(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	bool encap = efx_ef100_has_cap(nic_data->datapath_caps,
				       VXLAN_NVGRE);

	return efx_mcdi_filter_table_init(efx, true, encap);
}

static int ef100_filter_table_up(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	int rc = 0, rc2;

	down_write(&efx->filter_sem);
	if (nic_data->filters_up)
		goto out;

	rc = efx_mcdi_filter_table_up(efx);
out:
	nic_data->filters_up = !rc;
	up_write(&efx->filter_sem);

	if (!rc) {
		rc2 = efx_tc_insert_rep_filters(efx);
		if (rc2)
			netif_warn(efx, drv, efx->net_dev,
				   "Failed to insert representor filters, rc %d\n",
				   rc2);
	}
	return rc;
}

static void ef100_filter_table_down(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;

	efx_tc_remove_rep_filters(efx);

	down_write(&efx->filter_sem);
	if (!nic_data->filters_up)
		goto out;

	efx_mcdi_filter_table_down(efx);

	nic_data->filters_up = false;
out:
	up_write(&efx->filter_sem);
}

/*	Other
 */
static int ef100_reconfigure_mac(struct efx_nic *efx, bool mtu_only)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	int rc;

	WARN_ON(!mutex_is_locked(&efx->mac_lock));

	efx_mcdi_filter_sync_rx_mode(efx);

	rc = efx_mcdi_set_mac(efx);
	if (rc == -EPERM && mtu_only &&
	    efx_ef100_has_cap(nic_data->datapath_caps, SET_MAC_ENHANCED))
		rc = efx_mcdi_set_mtu(efx);
#ifdef EFX_NOT_UPSTREAM
	/* XXX temporary hack to allow VFs to set a software MTU
	 * See SWNETLINUX-4196, FWRIVERHD-1507.
	 */
	if (rc == -EPERM && efx->type->is_vf)
		return 0;
#endif
	return rc;
}


static enum reset_type ef100_map_reset_reason(enum reset_type reason)
{
	if (reason == RESET_TYPE_TX_WATCHDOG)
		return reason;
	return RESET_TYPE_DISABLE;
}

static int ef100_map_reset_flags(u32 *flags)
{
	/* Only perform a RESET_TYPE_ALL because we don't support MC_REBOOTs */
	if ((*flags & EF100_RESET_PORT)) {
		*flags &= ~EF100_RESET_PORT;
		return RESET_TYPE_ALL;
	}
	if (*flags & ETH_RESET_MGMT) {
		*flags &= ~ETH_RESET_MGMT;
		return RESET_TYPE_DISABLE;
	}

	return -EINVAL;
}

static int ef100_reset(struct efx_nic *efx, enum reset_type reset_type)
{
	int rc;

	if (efx->net_dev)
		dev_close(efx->net_dev);

	if (reset_type == RESET_TYPE_TX_WATCHDOG) {
		netif_device_attach(efx->net_dev);
		__clear_bit(reset_type, &efx->reset_pending);
		efx->state = STATE_NET_DOWN;
		rc = dev_open(efx->net_dev, NULL);
	} else if (reset_type == RESET_TYPE_ALL) {
		/* A RESET_TYPE_ALL will cause filters to be removed, so we remove filters
		 * and reprobe after reset to avoid removing filters twice
		 */
		ef100_filter_table_down(efx);
		rc = efx_mcdi_reset(efx, reset_type);
		if (rc)
			return rc;

		efx->last_reset = jiffies;
		netif_device_attach(efx->net_dev);

		rc = ef100_filter_table_up(efx);
		if (rc)
			return rc;

		rc = dev_open(efx->net_dev, NULL);
	} else {
		rc = 1;	/* Leave the device closed */
	}
	return rc;
}

static void ef100_common_stat_mask(unsigned long *mask)
{
	__set_bit(EF100_STAT_port_rx_packets, mask);
	__set_bit(EF100_STAT_port_tx_packets, mask);
	__set_bit(EF100_STAT_port_rx_bytes, mask);
	__set_bit(EF100_STAT_port_tx_bytes, mask);
	__set_bit(EF100_STAT_port_rx_multicast, mask);
	__set_bit(EF100_STAT_port_rx_bad, mask);
	__set_bit(EF100_STAT_port_rx_align_error, mask);
	__set_bit(EF100_STAT_port_rx_overflow, mask);
}

static void ef100_ethtool_stat_mask(unsigned long *mask)
{
	__set_bit(EF100_STAT_port_tx_pause, mask);
	__set_bit(EF100_STAT_port_tx_unicast, mask);
	__set_bit(EF100_STAT_port_tx_multicast, mask);
	__set_bit(EF100_STAT_port_tx_broadcast, mask);
	__set_bit(EF100_STAT_port_tx_lt64, mask);
	__set_bit(EF100_STAT_port_tx_64, mask);
	__set_bit(EF100_STAT_port_tx_65_to_127, mask);
	__set_bit(EF100_STAT_port_tx_128_to_255, mask);
	__set_bit(EF100_STAT_port_tx_256_to_511, mask);
	__set_bit(EF100_STAT_port_tx_512_to_1023, mask);
	__set_bit(EF100_STAT_port_tx_1024_to_15xx, mask);
	__set_bit(EF100_STAT_port_tx_15xx_to_jumbo, mask);
	__set_bit(EF100_STAT_port_rx_good, mask);
	__set_bit(EF100_STAT_port_rx_bad_bytes, mask);
	__set_bit(EF100_STAT_port_rx_pause, mask);
	__set_bit(EF100_STAT_port_rx_unicast, mask);
	__set_bit(EF100_STAT_port_rx_broadcast, mask);
	__set_bit(EF100_STAT_port_rx_lt64, mask);
	__set_bit(EF100_STAT_port_rx_64, mask);
	__set_bit(EF100_STAT_port_rx_65_to_127, mask);
	__set_bit(EF100_STAT_port_rx_128_to_255, mask);
	__set_bit(EF100_STAT_port_rx_256_to_511, mask);
	__set_bit(EF100_STAT_port_rx_512_to_1023, mask);
	__set_bit(EF100_STAT_port_rx_1024_to_15xx, mask);
	__set_bit(EF100_STAT_port_rx_15xx_to_jumbo, mask);
	__set_bit(EF100_STAT_port_rx_gtjumbo, mask);
	__set_bit(EF100_STAT_port_rx_bad_gtjumbo, mask);
	__set_bit(EF100_STAT_port_rx_length_error, mask);
	__set_bit(EF100_STAT_port_rx_nodesc_drops, mask);
	__set_bit(GENERIC_STAT_rx_nodesc_trunc, mask);
	__set_bit(GENERIC_STAT_rx_noskb_drops, mask);
}

#define EF100_DMA_STAT(ext_name, mcdi_name)			\
	[EF100_STAT_ ## ext_name] =				\
	{ #ext_name, 64, 8 * MC_CMD_MAC_ ## mcdi_name }

static const struct efx_hw_stat_desc ef100_stat_desc[EF100_STAT_COUNT] = {
	EF100_DMA_STAT(port_tx_bytes, TX_BYTES),
	EF100_DMA_STAT(port_tx_packets, TX_PKTS),
	EF100_DMA_STAT(port_tx_pause, TX_PAUSE_PKTS),
	EF100_DMA_STAT(port_tx_unicast, TX_UNICAST_PKTS),
	EF100_DMA_STAT(port_tx_multicast, TX_MULTICAST_PKTS),
	EF100_DMA_STAT(port_tx_broadcast, TX_BROADCAST_PKTS),
	EF100_DMA_STAT(port_tx_lt64, TX_LT64_PKTS),
	EF100_DMA_STAT(port_tx_64, TX_64_PKTS),
	EF100_DMA_STAT(port_tx_65_to_127, TX_65_TO_127_PKTS),
	EF100_DMA_STAT(port_tx_128_to_255, TX_128_TO_255_PKTS),
	EF100_DMA_STAT(port_tx_256_to_511, TX_256_TO_511_PKTS),
	EF100_DMA_STAT(port_tx_512_to_1023, TX_512_TO_1023_PKTS),
	EF100_DMA_STAT(port_tx_1024_to_15xx, TX_1024_TO_15XX_PKTS),
	EF100_DMA_STAT(port_tx_15xx_to_jumbo, TX_15XX_TO_JUMBO_PKTS),
	EF100_DMA_STAT(port_rx_bytes, RX_BYTES),
	EF100_DMA_STAT(port_rx_packets, RX_PKTS),
	EF100_DMA_STAT(port_rx_good, RX_GOOD_PKTS),
	EF100_DMA_STAT(port_rx_bad, RX_BAD_FCS_PKTS),
	EF100_DMA_STAT(port_rx_bad_bytes, RX_BAD_BYTES),
	EF100_DMA_STAT(port_rx_pause, RX_PAUSE_PKTS),
	EF100_DMA_STAT(port_rx_unicast, RX_UNICAST_PKTS),
	EF100_DMA_STAT(port_rx_multicast, RX_MULTICAST_PKTS),
	EF100_DMA_STAT(port_rx_broadcast, RX_BROADCAST_PKTS),
	EF100_DMA_STAT(port_rx_lt64, RX_UNDERSIZE_PKTS),
	EF100_DMA_STAT(port_rx_64, RX_64_PKTS),
	EF100_DMA_STAT(port_rx_65_to_127, RX_65_TO_127_PKTS),
	EF100_DMA_STAT(port_rx_128_to_255, RX_128_TO_255_PKTS),
	EF100_DMA_STAT(port_rx_256_to_511, RX_256_TO_511_PKTS),
	EF100_DMA_STAT(port_rx_512_to_1023, RX_512_TO_1023_PKTS),
	EF100_DMA_STAT(port_rx_1024_to_15xx, RX_1024_TO_15XX_PKTS),
	EF100_DMA_STAT(port_rx_15xx_to_jumbo, RX_15XX_TO_JUMBO_PKTS),
	EF100_DMA_STAT(port_rx_gtjumbo, RX_GTJUMBO_PKTS),
	EF100_DMA_STAT(port_rx_bad_gtjumbo, RX_JABBER_PKTS),
	EF100_DMA_STAT(port_rx_align_error, RX_ALIGN_ERROR_PKTS),
	EF100_DMA_STAT(port_rx_length_error, RX_LENGTH_ERROR_PKTS),
	EF100_DMA_STAT(port_rx_overflow, RX_OVERFLOW_PKTS),
	EF100_DMA_STAT(port_rx_nodesc_drops, RX_NODESC_DROPS),
	EFX_GENERIC_SW_STAT(rx_nodesc_trunc),
	EFX_GENERIC_SW_STAT(rx_noskb_drops),
};

static size_t ef100_describe_stats(struct efx_nic *efx, u8 *names)
{
	DECLARE_BITMAP(mask, EF100_STAT_COUNT) = {};

	ef100_ethtool_stat_mask(mask);
	return efx_nic_describe_stats(ef100_stat_desc, EF100_STAT_COUNT,
				      mask, names);
}

static size_t ef100_update_stats_common(struct efx_nic *efx, u64 *full_stats,
					struct rtnl_link_stats64 *core_stats)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	DECLARE_BITMAP(mask, EF100_STAT_COUNT) = {};
	size_t stats_count = 0, index;
	u64 *stats = nic_data->stats;

	ef100_ethtool_stat_mask(mask);

	if (full_stats) {
		for_each_set_bit(index, mask, EF100_STAT_COUNT) {
			if (ef100_stat_desc[index].name) {
				*full_stats++ = stats[index];
				++stats_count;
			}
		}
	}

	if (!core_stats)
		return stats_count;

	core_stats->rx_packets = stats[EF100_STAT_port_rx_packets];
	core_stats->tx_packets = stats[EF100_STAT_port_tx_packets];
	core_stats->rx_bytes = stats[EF100_STAT_port_rx_bytes];
	core_stats->tx_bytes = stats[EF100_STAT_port_tx_bytes];
	core_stats->rx_dropped = stats[EF100_STAT_port_rx_nodesc_drops] +
				 stats[GENERIC_STAT_rx_nodesc_trunc] +
				 stats[GENERIC_STAT_rx_noskb_drops];
	core_stats->multicast = stats[EF100_STAT_port_rx_multicast];
	core_stats->rx_length_errors =
			stats[EF100_STAT_port_rx_gtjumbo] +
			stats[EF100_STAT_port_rx_length_error];
	core_stats->rx_crc_errors = stats[EF100_STAT_port_rx_bad];
	core_stats->rx_frame_errors =
			stats[EF100_STAT_port_rx_align_error];
	core_stats->rx_fifo_errors = stats[EF100_STAT_port_rx_overflow];
	core_stats->rx_errors = (core_stats->rx_length_errors +
				 core_stats->rx_crc_errors +
				 core_stats->rx_frame_errors);

	return stats_count;
}

static size_t ef100_update_stats(struct efx_nic *efx,
				 u64 *full_stats,
				 struct rtnl_link_stats64 *core_stats)
	__acquires(efx->stats_lock)
{
	__le64 *mc_stats = kmalloc(efx->num_mac_stats * sizeof(__le64), GFP_ATOMIC);
	struct ef100_nic_data *nic_data = efx->nic_data;
	DECLARE_BITMAP(mask, EF100_STAT_COUNT) = {};
	u64 *stats = nic_data->stats;

	spin_lock_bh(&efx->stats_lock);

	ef100_common_stat_mask(mask);
	ef100_ethtool_stat_mask(mask);

	efx_nic_copy_stats(efx, mc_stats);
	efx_nic_update_stats(ef100_stat_desc, EF100_STAT_COUNT, mask,
			     stats,
			     efx->mc_initial_stats, mc_stats);

	kfree(mc_stats);

#if 0   /* Not all stats have been coded yet */
	/* Update derived statistics */
	efx_nic_fix_nodesc_drop_stat(efx,
				     &stats[EF100_STAT_port_rx_nodesc_drops]);
	/* MC Firmware reads RX_BYTES and RX_GOOD_BYTES from the MAC.
	 * It then calculates RX_BAD_BYTES and DMAs it to us with RX_BYTES.
	 * We report these as port_rx_ stats. We are not given RX_GOOD_BYTES.
	 * Here we calculate port_rx_good_bytes.
	 */
	stats[EF100_STAT_port_rx_good_bytes] =
		stats[EF100_STAT_port_rx_bytes] -
		stats[EF100_STAT_port_rx_bytes_minus_good_bytes];

	/* The asynchronous reads used to calculate RX_BAD_BYTES in
	 * MC Firmware are done such that we should not see an increase in
	 * RX_BAD_BYTES when a good packet has arrived. Unfortunately this
	 * does mean that the stat can decrease at times. Here we do not
	 * update the stat unless it has increased or has gone to zero
	 * (In the case of the NIC rebooting).
	 * Please see Bug 33781 for a discussion of why things work this way.
	 */
	efx_update_diff_stat(&stats[EF100_STAT_port_rx_bad_bytes],
			     stats[EF100_STAT_port_rx_bytes_minus_good_bytes]);
	efx_update_sw_stats(efx, stats);
#endif

	return ef100_update_stats_common(efx, full_stats, core_stats);
}

static void ef100_pull_stats(struct efx_nic *efx)
{
	efx_mcdi_mac_pull_stats(efx);
	if (!efx->stats_initialised) {
		efx_reset_sw_stats(efx);
		efx_ptp_reset_stats(efx);
		efx_nic_reset_stats(efx);
		efx->stats_initialised = true;
	}
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_NEED_GET_PHYS_PORT_ID)
static int efx_ef100_get_phys_port_id(struct efx_nic *efx,
				      struct netdev_phys_item_id *ppid)
{
	struct ef100_nic_data *nic_data = efx->nic_data;

	if (!is_valid_ether_addr(nic_data->port_id))
		return -EOPNOTSUPP;

	ppid->id_len = ETH_ALEN;
	memcpy(ppid->id, nic_data->port_id, ppid->id_len);

	return 0;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
static struct net_device *ef100_get_vf_rep(struct efx_nic *efx, unsigned int vf)
{
#if defined(CONFIG_SFC_SRIOV)
	struct ef100_nic_data *nic_data = efx->nic_data;

	if (vf < efx->vf_count)
		return nic_data->vf_rep[vf];
#endif
	return NULL;
}

static struct net_device *ef100_get_remote_rep(struct efx_nic *efx,
					       unsigned int i)
{
	struct ef100_nic_data *nic_data = efx->nic_data;

	if (i < nic_data->rem_rep_count)
		return nic_data->rem_rep[i];
	return NULL;
}

static void ef100_detach_remote_reps(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct net_device *rep_dev;
	unsigned int i;

	netif_dbg(efx, drv, efx->net_dev, "Detaching %d remote reps\n",
		  nic_data->rem_rep_count);
	assert_spin_locked(&nic_data->rem_reps_lock);
	for (i = 0; i < nic_data->rem_rep_count; i++) {
		rep_dev = nic_data->rem_rep[i];
		netif_carrier_off(rep_dev);
		/* See efx_device_detach_sync() */
		netif_tx_lock_bh(rep_dev);
		netif_tx_stop_all_queues(rep_dev);
		netif_tx_unlock_bh(rep_dev);
	}
}

static void ef100_attach_remote_reps(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	unsigned int i;

	netif_dbg(efx, drv, efx->net_dev, "Attaching %d remote reps\n",
		  nic_data->rem_rep_count);
	assert_spin_locked(&nic_data->rem_reps_lock);
	for (i = 0; i < nic_data->rem_rep_count; i++) {
		netif_tx_wake_all_queues(nic_data->rem_rep[i]);
		netif_carrier_on(nic_data->rem_rep[i]);
	}
}

void __ef100_detach_reps(struct efx_nic *efx)
{
#if defined(CONFIG_SFC_SRIOV)
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct net_device *rep_dev;
	unsigned int vf;

	netif_dbg(efx, drv, efx->net_dev, "Detaching %d vfreps\n",
		  nic_data->vf_rep_count);
	for (vf = 0; vf < nic_data->vf_rep_count; vf++) {
		rep_dev = nic_data->vf_rep[vf];
		netif_carrier_off(rep_dev);
		/* See efx_device_detach_sync() */
		netif_tx_lock_bh(rep_dev);
		netif_tx_stop_all_queues(rep_dev);
		netif_tx_unlock_bh(rep_dev);
	}
#endif
}

static void ef100_detach_reps(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;

	spin_lock_bh(&nic_data->vf_reps_lock);
	__ef100_detach_reps(efx);
	spin_unlock_bh(&nic_data->vf_reps_lock);
	spin_lock_bh(&nic_data->rem_reps_lock);
	ef100_detach_remote_reps(efx);
	spin_unlock_bh(&nic_data->rem_reps_lock);
}

void __ef100_attach_reps(struct efx_nic *efx)
{
#if defined(CONFIG_SFC_SRIOV)
	struct ef100_nic_data *nic_data = efx->nic_data;
	unsigned int vf;

	netif_dbg(efx, drv, efx->net_dev, "Attaching %d vfreps\n",
		  nic_data->vf_rep_count);
	for (vf = 0; vf < nic_data->vf_rep_count; vf++) {
		netif_tx_wake_all_queues(nic_data->vf_rep[vf]);
		netif_carrier_on(nic_data->vf_rep[vf]);
	}
#endif
}

static void ef100_attach_reps(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;

	spin_lock_bh(&nic_data->vf_reps_lock);
	__ef100_attach_reps(efx);
	spin_unlock_bh(&nic_data->vf_reps_lock);
	spin_lock_bh(&nic_data->rem_reps_lock);
	ef100_attach_remote_reps(efx);
	spin_unlock_bh(&nic_data->rem_reps_lock);
}
#else /* EFX_TC_OFFLOAD */
void __ef100_detach_reps(struct efx_nic *efx)
{
}

void __ef100_attach_reps(struct efx_nic *efx)
{
}
#endif

#if defined(EFX_USE_KCOMPAT) && defined(EFX_TC_OFFLOAD) && !defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER) && !defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER)
static struct ef100_udp_tunnel *__efx_ef100_udp_tnl_find_port(
			struct ef100_nic_data *nic_data, __be16 port)
			__must_hold(nic_data->udp_tunnels_lock)
{
	struct ef100_udp_tunnel *tnl;

	list_for_each_entry(tnl, &nic_data->udp_tunnels, list)
		if (port == tnl->port)
			return tnl;
	return NULL;
}

static void efx_ef100_udp_tnl_add_port(struct efx_nic *efx,
				       struct ef100_udp_tunnel tnl)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct ef100_udp_tunnel *entry;

	spin_lock(&nic_data->udp_tunnels_lock);
	entry = __efx_ef100_udp_tnl_find_port(nic_data, tnl.port);
	if (entry) /* EEXIST */
		goto out;
	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) /* ENOMEM */
		goto out;
	*entry = tnl;
	list_add_tail(&entry->list, &nic_data->udp_tunnels);
out:
	spin_unlock(&nic_data->udp_tunnels_lock);
}

enum efx_encap_type efx_ef100_udp_tnl_lookup_port(struct efx_nic *efx,
						  __be16 port)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct ef100_udp_tunnel *entry;
	enum efx_encap_type rc;

	spin_lock(&nic_data->udp_tunnels_lock);
	entry = __efx_ef100_udp_tnl_find_port(nic_data, port);
	if (entry)
		rc = entry->type;
	else
		rc = EFX_ENCAP_TYPE_NONE;
	spin_unlock(&nic_data->udp_tunnels_lock);
	return rc;
}

static void efx_ef100_udp_tnl_del_port(struct efx_nic *efx,
				       struct ef100_udp_tunnel tnl)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct ef100_udp_tunnel *entry;

	spin_lock(&nic_data->udp_tunnels_lock);
	entry = __efx_ef100_udp_tnl_find_port(nic_data, tnl.port);
	if (entry && entry->type == tnl.type) {
		list_del(&entry->list);
		kfree(entry);
	}
	spin_unlock(&nic_data->udp_tunnels_lock);
}
#endif

static int efx_ef100_irq_test_generate(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_TRIGGER_INTERRUPT_IN_LEN);

	BUILD_BUG_ON(MC_CMD_TRIGGER_INTERRUPT_OUT_LEN != 0);

	MCDI_SET_DWORD(inbuf, TRIGGER_INTERRUPT_IN_INTR_LEVEL, efx->irq_level);
	return efx_mcdi_rpc_quiet(efx, MC_CMD_TRIGGER_INTERRUPT,
				  inbuf, sizeof(inbuf), NULL, 0, NULL);
}

static void efx_ef100_ev_test_generate(struct efx_channel *channel)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_DRIVER_EVENT_IN_LEN);
	struct efx_nic *efx = channel->efx;
	efx_qword_t event;
	int rc;

	EFX_POPULATE_QWORD_2(event,
			     ESF_GZ_E_TYPE, ESE_GZ_EF100_EV_DRIVER,
			     ESF_GZ_DRIVER_DATA, EFX_EF100_TEST);

	MCDI_SET_DWORD(inbuf, DRIVER_EVENT_IN_EVQ, channel->channel);

	/* MCDI_SET_QWORD is not appropriate here since EFX_POPULATE_* has
	 * already swapped the data to little-endian order.
	 */
	memcpy(MCDI_PTR(inbuf, DRIVER_EVENT_IN_DATA), &event.u64[0],
	       sizeof(efx_qword_t));

	rc = efx_mcdi_rpc(efx, MC_CMD_DRIVER_EVENT, inbuf, sizeof(inbuf),
			  NULL, 0, NULL);
	if (rc && (rc != -ENETDOWN))
		goto fail;

	return;

fail:
	WARN_ON(true);
	netif_err(efx, hw, efx->net_dev, "%s: failed rc=%d\n", __func__, rc);
}

static unsigned int efx_ef100_mcdi_rpc_timeout(struct efx_nic *efx,
					       unsigned int cmd)
{
	switch (cmd) {
	case MC_CMD_NVRAM_ERASE:
	case MC_CMD_NVRAM_UPDATE_FINISH:
#ifdef EFX_C_MODEL
	case MC_CMD_ENTITY_RESET:
#endif
		return MCDI_RPC_LONG_TIMEOUT;
	default:
		return MCDI_RPC_TIMEOUT;
	}
}

static unsigned int ef100_check_caps(const struct efx_nic *efx,
				     u8 flag,
				     u32 offset)
{
	const struct ef100_nic_data *nic_data = efx->nic_data;

	switch (offset) {
	case(MC_CMD_GET_CAPABILITIES_V8_OUT_FLAGS1_OFST):
		return nic_data->datapath_caps & BIT_ULL(flag);
	case(MC_CMD_GET_CAPABILITIES_V8_OUT_FLAGS2_OFST):
		return nic_data->datapath_caps2 & BIT_ULL(flag);
	default: return 0;
	}
}

static int efx_ef100_get_base_mport(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	u32 selector, id;
	int rc;

	/* Construct mport selector for "physical network port" */
	efx_mae_mport_wire(efx, &selector);
	/* Look up actual mport ID */
	rc = efx_mae_lookup_mport(efx, selector, &id);
	if (rc)
		return rc;
	/* The ID should always fit in 16 bits, because that's how wide the
	 * corresponding fields in the RX prefix & TX override descriptor are
	 */
	if (id >> 16)
		netif_warn(efx, probe, efx->net_dev, "Bad base m-port id %#x\n",
			   id);
	nic_data->base_mport = id;
	nic_data->have_mport = true;

	/* For compat with older C models, we also need a destination base
	 * mport.  XXX remove after C-model flag day
	 */
	/* Construct mport selector for "calling PF" */
	efx_mae_mport_uplink(efx, &selector);
	/* Look up actual mport ID */
	rc = efx_mae_lookup_mport(efx, selector, &id);
	if (rc)
		return rc;
	if (id >> 16)
		netif_warn(efx, probe, efx->net_dev, "Bad oldbase m-port id %#x\n",
			   id);
	nic_data->old_base_mport = id;
	nic_data->have_old_mport = true;
	return 0;
}

/* BAR configuration.
 * To change BAR configuration we tear down the current configuration (which
 * leaves the hardware in the PROBED state), and then initialise the new
 * BAR state.
 */
static struct {
	int (*init)(struct efx_probe_data *probe_data);
	void (*fini)(struct efx_probe_data *probe_data);
} bar_config_std[] = {
	[EF100_BAR_CONFIG_EF100] = {
		.init = ef100_probe_netdev,
		.fini = ef100_remove_netdev
	},
#ifdef CONFIG_SFC_VDPA
	[EF100_BAR_CONFIG_VDPA] = {
		.init = ef100_vdpa_init,
		.fini = ef100_vdpa_fini
	},
#endif
#ifdef EFX_NOT_UPSTREAM
	[EF100_BAR_CONFIG_NONE] = {
		.init = NULL,
		.fini = NULL
	},
#endif
};

static ssize_t bar_config_show(struct device *dev,
			       struct device_attribute *attr, char *buf_out)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	struct ef100_nic_data *nic_data = efx->nic_data;

	switch (nic_data->bar_config) {
	case EF100_BAR_CONFIG_EF100:
		scnprintf(buf_out, PAGE_SIZE, "EF100\n");
		break;
#ifdef CONFIG_SFC_VDPA
	case EF100_BAR_CONFIG_VDPA:
		scnprintf(buf_out, PAGE_SIZE, "vDPA\n");
		break;
#endif
#ifdef EFX_NOT_UPSTREAM
	case EF100_BAR_CONFIG_NONE:
		scnprintf(buf_out, PAGE_SIZE, "None\n");
		break;
#endif
	default: /* this should not happen */
		WARN_ON_ONCE(1);
		return 0;
	}

	return strlen(buf_out);
}

static ssize_t bar_config_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));
	struct ef100_nic_data *nic_data = efx->nic_data;
	enum ef100_bar_config new_config, old_config;
	struct efx_probe_data *probe_data;
	int rc;

	/* Current EF100 hardware supports vDPA on VFs only
	 * (see SF-122427-SW)
	 */
	if (!efx->type->is_vf &&
	    !strncasecmp(buf, "vdpa", min_t(size_t, count, 4))) {
		pci_err(efx->pci_dev, "vdpa over PF not supported : %s",
			efx->name);
		return -EOPNOTSUPP;
	}

#ifdef CONFIG_SFC_VDPA
	mutex_lock(&nic_data->bar_config_lock);
#endif
	if (!strncasecmp(buf, "ef100", min_t(size_t, count, 5)))
		new_config = EF100_BAR_CONFIG_EF100;
#ifdef CONFIG_SFC_VDPA
	else if (!strncasecmp(buf, "vdpa", min_t(size_t, count, 4)))
		new_config = EF100_BAR_CONFIG_VDPA;
#endif
#ifdef EFX_NOT_UPSTREAM
	else if (!strncasecmp(buf, "none", min_t(size_t, count, 4)))
		new_config = EF100_BAR_CONFIG_NONE;
#endif
	else {
#ifdef CONFIG_SFC_VDPA
		mutex_unlock(&nic_data->bar_config_lock);
#endif
		return -EIO;
	}
	old_config = nic_data->bar_config;
	if (new_config == old_config) {
#ifdef CONFIG_SFC_VDPA
		mutex_unlock(&nic_data->bar_config_lock);
#endif
		return count;
	}

#ifdef CONFIG_SFC_VDPA
	if (old_config == EF100_BAR_CONFIG_VDPA &&
	    new_config == EF100_BAR_CONFIG_EF100) {
		if (ef100_vdpa_dev_in_use(efx)) {
			pci_warn(efx->pci_dev,
				 "Device in use. Cannot change bar config");
			mutex_unlock(&nic_data->bar_config_lock);
			return -EBUSY;
		}
	}
#endif
	probe_data = container_of(efx, struct efx_probe_data, efx);
	if (bar_config_std[old_config].fini)
		bar_config_std[old_config].fini(probe_data);

	nic_data->bar_config = new_config;
	if (bar_config_std[new_config].init) {
		rc = bar_config_std[new_config].init(probe_data);
		if (rc) {
#ifdef CONFIG_SFC_VDPA
			mutex_unlock(&nic_data->bar_config_lock);
#endif
			return rc;
		}
	}

#ifdef CONFIG_SFC_VDPA
	mutex_unlock(&nic_data->bar_config_lock);
#endif

	pci_info(efx->pci_dev, "BAR configuration changed to %s", buf);
	return count;
}

static DEVICE_ATTR_RW(bar_config);

enum ef100_tlv_state_machine {
	EF100_TLV_TYPE,
	EF100_TLV_TYPE_CONT,
	EF100_TLV_LENGTH,
	EF100_TLV_VALUE
};

struct ef100_tlv_state {
	enum ef100_tlv_state_machine state;
	u64 value;
	u32 value_offset;
	u16 type;
	u8 len;
};

static int ef100_tlv_feed(struct ef100_tlv_state *state, u8 byte)
{
	switch (state->state) {
	case EF100_TLV_TYPE:
		state->type = byte & 0x7f;
		state->state = (byte & 0x80) ? EF100_TLV_TYPE_CONT
					     : EF100_TLV_LENGTH;
		/* Clear ready to read in a new entry */
		state->value = 0;
		state->value_offset = 0;
		return 0;
	case EF100_TLV_TYPE_CONT:
		state->type |= byte << 7;
		state->state = EF100_TLV_LENGTH;
		return 0;
	case EF100_TLV_LENGTH:
		state->len = byte;
		/* We only handle TLVs that fit in a u64 */
		if (state->len > sizeof(state->value))
			return -EOPNOTSUPP;
		/* len may be zero, implying a value of zero */
		state->state = state->len ? EF100_TLV_VALUE : EF100_TLV_TYPE;
		return 0;
	case EF100_TLV_VALUE:
		state->value |= ((u64)byte) << (state->value_offset * 8);
		state->value_offset++;
		if (state->value_offset >= state->len)
			state->state = EF100_TLV_TYPE;
		return 0;
	default: /* state machine error, can't happen */
		WARN_ON_ONCE(1);
		return -EIO;
	}
}

static int ef100_process_design_param(struct efx_nic *efx,
				      const struct ef100_tlv_state *reader)
{
	struct ef100_nic_data *nic_data = efx->nic_data;

	switch (reader->type) {
	case ESE_EF100_DP_GZ_PAD: /* padding, skip it */
		return 0;
	case ESE_EF100_DP_GZ_PARTIAL_TSTAMP_SUB_NANO_BITS:
		/* Driver doesn't support timestamping yet, so we don't care */
		return 0;
	case ESE_EF100_DP_GZ_EVQ_UNSOL_CREDIT_SEQ_BITS:
		/* Driver doesn't support unsolicited-event credits yet, so
		 * we don't care
		 */
		return 0;
	case ESE_EF100_DP_GZ_NMMU_GROUP_SIZE:
		/* Driver doesn't manage the NMMU (so we don't care) */
		return 0;
	case ESE_EF100_DP_GZ_RX_L4_CSUM_PROTOCOLS:
		/* Driver uses CHECKSUM_COMPLETE, so we don't care about
		 * protocol checksum validation
		 */
		return 0;
	case ESE_EF100_DP_GZ_TSO_MAX_HDR_LEN:
		nic_data->tso_max_hdr_len = min_t(u64, reader->value, 0xffff);
		return 0;
	case ESE_EF100_DP_GZ_TSO_MAX_HDR_NUM_SEGS:
		/* We always put HDR_NUM_SEGS=1 in our TSO descriptors */
		if (!reader->value) {
			netif_err(efx, probe, efx->net_dev,
				  "TSO_MAX_HDR_NUM_SEGS < 1\n");
			return -EOPNOTSUPP;
		}
		return 0;
	case ESE_EF100_DP_GZ_RXQ_SIZE_GRANULARITY:
	case ESE_EF100_DP_GZ_TXQ_SIZE_GRANULARITY:
		/* Our TXQ and RXQ sizes are always power-of-two and thus divisible by
		 * EFX_MIN_DMAQ_SIZE, so we just need to check that
		 * EFX_MIN_DMAQ_SIZE is divisible by GRANULARITY.
		 * This is very unlikely to fail.
		 */
		if (!reader->value || reader->value > efx_min_dmaq_size(efx) ||
		    efx_min_dmaq_size(efx) % (u32)reader->value) {
			netif_err(efx, probe, efx->net_dev,
				  "%s size granularity is %llu, can't guarantee safety\n",
				  reader->type == ESE_EF100_DP_GZ_RXQ_SIZE_GRANULARITY ? "RXQ" : "TXQ",
				  reader->value);
			return -EOPNOTSUPP;
		}
		return 0;
	case ESE_EF100_DP_GZ_TSO_MAX_PAYLOAD_LEN:
		nic_data->tso_max_payload_len = min_t(u64, reader->value, GSO_MAX_SIZE);
		efx->net_dev->gso_max_size = nic_data->tso_max_payload_len;
		return 0;
	case ESE_EF100_DP_GZ_TSO_MAX_PAYLOAD_NUM_SEGS:
		nic_data->tso_max_payload_num_segs = min_t(u64, reader->value, 0xffff);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_GSO_MAX_SEGS)
		efx->net_dev->gso_max_segs = nic_data->tso_max_payload_num_segs;
#endif
		return 0;
	case ESE_EF100_DP_GZ_TSO_MAX_NUM_FRAMES:
		nic_data->tso_max_frames = min_t(u64, reader->value, 0xffff);
		return 0;
	case ESE_EF100_DP_GZ_COMPAT:
		if (reader->value) {
			netif_err(efx, probe, efx->net_dev,
				  "DP_COMPAT has unknown bits %#llx, driver not compatible with this hw\n",
				  reader->value);
			return -EOPNOTSUPP;
		}
		return 0;
	case ESE_EF100_DP_GZ_MEM2MEM_MAX_LEN:
		/* Driver doesn't use mem2mem transfers */
		return 0;
	case ESE_EF100_DP_GZ_EVQ_TIMER_TICK_NANOS:
		/* Driver doesn't currently use EVQ_TIMER */
		return 0;
	case ESE_EF100_DP_GZ_NMMU_PAGE_SIZES:
		/* Driver doesn't manage the NMMU (so we don't care) */
		return 0;
	case ESE_EF100_DP_GZ_VI_STRIDES:
		/* We never try to set the VI stride, and we don't rely on
		 * being able to find VIs past VI 0 until after we've learned
		 * the current stride from MC_CMD_GET_CAPABILITIES.
		 * So the value of this shouldn't matter.
		 */
		if (reader->value != ESE_EF100_DP_GZ_VI_STRIDES_DEFAULT)
			netif_dbg(efx, probe, efx->net_dev,
				  "NIC has other than default VI_STRIDES (mask "
				  "%#llx), early probing might use wrong one\n",
				  reader->value);
		return 0;
	case ESE_EF100_DP_GZ_RX_MAX_RUNT:
		/* Driver doesn't look at L2_STATUS:LEN_ERR bit, so we don't
		 * care whether it indicates runt or overlength for any given
		 * packet, so we don't care about this parameter.
		 */
		return 0;
	default:
		/* Host interface says "Drivers should ignore design parameters
		 * that they do not recognise."
		 */
		netif_info(efx, probe, efx->net_dev,
			   "Ignoring unrecognised design parameter %u\n",
			   reader->type);
		return 0;
	}
}

static int ef100_check_design_params(struct efx_nic *efx)
{
	struct ef100_tlv_state reader = {};
	u32 total_len, offset = 0;
	efx_dword_t reg;
	int rc = 0, i;
	u32 data;

	efx_readd(efx, &reg, ER_GZ_PARAMS_TLV_LEN);
	total_len = EFX_DWORD_FIELD(reg, EFX_DWORD_0);
	pci_dbg(efx->pci_dev, "%u bytes of design parameters\n", total_len);
	while (offset < total_len) {
		efx_readd(efx, &reg, ER_GZ_PARAMS_TLV + offset);
		data = EFX_DWORD_FIELD(reg, EFX_DWORD_0);
		for (i = 0; i < sizeof(data); i++) {
			rc = ef100_tlv_feed(&reader, data);
			/* Got a complete value? */
			if (!rc && reader.state == EF100_TLV_TYPE)
				rc = ef100_process_design_param(efx, &reader);
			if (rc)
				goto out;
			data >>= 8;
			offset++;
		}
	}
out:
	return rc;
}

/*	NIC probe and remove
 */
static int ef100_probe_main(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data;
	unsigned int bar_size =
		resource_size(&efx->pci_dev->resource[efx->mem_bar]);
	u32 privlege_mask = 0;
	int i, rc;

	if (WARN_ON(bar_size == 0))
		return -EIO;

	nic_data = kzalloc(sizeof(*nic_data), GFP_KERNEL);
	if (!nic_data)
		return -ENOMEM;
	efx->nic_data = nic_data;
	nic_data->efx = efx;
	spin_lock_init(&nic_data->vf_reps_lock);
	spin_lock_init(&nic_data->rem_reps_lock);
#if defined(EFX_USE_KCOMPAT) && defined(EFX_TC_OFFLOAD) && !defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER) && !defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER)
	spin_lock_init(&nic_data->udp_tunnels_lock);
	INIT_LIST_HEAD(&nic_data->udp_tunnels);
#endif
	efx->max_vis = EF100_MAX_VIS;

	/* Populate design-parameter defaults */
	nic_data->tso_max_hdr_len = ESE_EF100_DP_GZ_TSO_MAX_HDR_LEN_DEFAULT;
	nic_data->tso_max_frames = ESE_EF100_DP_GZ_TSO_MAX_NUM_FRAMES_DEFAULT;
	nic_data->tso_max_payload_num_segs = ESE_EF100_DP_GZ_TSO_MAX_PAYLOAD_NUM_SEGS_DEFAULT;
	nic_data->tso_max_payload_len = ESE_EF100_DP_GZ_TSO_MAX_PAYLOAD_LEN_DEFAULT;
	/* Read design parameters */
	rc = ef100_check_design_params(efx);
	if (rc) {
		pci_err(efx->pci_dev, "Unsupported design parameters\n");
		goto fail;
	}

	/* we assume later that we can copy from this buffer in dwords */
	BUILD_BUG_ON(MCDI_CTL_SDU_LEN_MAX_V2 % 4);

	/* MCDI buffers must be 256 byte aligned. */
	rc = efx_nic_alloc_buffer(efx, &nic_data->mcdi_buf, MCDI_BUF_LEN,
				  GFP_KERNEL);
	if (rc)
		goto fail;

       efx->mcdi_buf_mode = EFX_BUF_MODE_EF100;

	/* Get the MC's warm boot count.  In case it's rebooting right
	 * now, be prepared to retry.
	 */
	i = 0;
	for (;;) {
		rc = ef100_get_warm_boot_count(efx);
		if (rc >= 0)
			break;
		if (++i == 5)
			goto fail;
		ssleep(1);
	}
	nic_data->warm_boot_count = rc;

	/* In case we're recovering from a crash (kexec), we want to
	 * cancel any outstanding request by the previous user of this
	 * function.  We send a special message using the least
	 * significant bits of the 'high' (doorbell) register.
	 */
	_efx_writed(efx, cpu_to_le32(1), efx_reg(efx, ER_GZ_MC_DB_HWRD));

	/* Post-IO section. */

	rc = efx_probe_common(efx);
	if (rc)
		goto fail;
	if (efx->mcdi->fn_flags &
	    (1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_NO_ACTIVE_PORT)) {
		pci_info(efx->pci_dev, "No network port on this PCI function");
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_TC_OFFLOAD)
		return 0;
#else
		/* N.B. Interfaces with no network port will have port_num set
		 * implicitly to zero.  This will affect the MAC stats. */
#endif
	} else {
		rc = efx_mcdi_port_get_number(efx);
		if (rc < 0)
			goto fail;
		efx->port_num = rc;
	}

	rc = efx_get_fn_info(efx, &nic_data->pf_index, &nic_data->vf_index);
	if (rc)
		goto fail;

	efx_mcdi_get_privilege_mask(efx, &privlege_mask);
	nic_data->grp_mae = !!(privlege_mask &
			       MC_CMD_PRIVILEGE_MASK_IN_GRP_MAE);

#ifdef CONFIG_SFC_VDPA
	mutex_init(&nic_data->bar_config_lock);
#endif

	rc = device_create_file(&efx->pci_dev->dev, &dev_attr_bar_config);

	return 0;
fail:
	return rc;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
static bool ef100_mport_needs_rep(struct efx_nic *efx,
				  struct mae_mport_desc *mport_desc)
{
	bool vnic, pcie_func, local_intf, local_pf, vf, self;
	struct ef100_nic_data *nic_data = efx->nic_data;

	vnic = mport_desc->mport_type == MAE_MPORT_DESC_MPORT_TYPE_VNIC;
	self = vnic && nic_data->have_old_mport &&
	       mport_desc->mport_id == nic_data->old_base_mport;
	pcie_func = vnic &&
		    mport_desc->vnic_client_type == MAE_MPORT_DESC_VNIC_CLIENT_TYPE_FUNCTION;
	vf = pcie_func && mport_desc->vf_idx != MAE_MPORT_DESC_VF_IDX_NULL;
	local_intf = nic_data->have_local_intf && pcie_func &&
		     mport_desc->interface_idx == nic_data->local_mae_intf;
	local_pf = pcie_func && mport_desc->pf_idx == nic_data->pf_index;
	WARN_ON(self && !local_pf);

	/* All VNICs, even VNIC_PLUGIN require rep.
	 * But no reps for ourself, or for our VFs (if we can identify them)
	 */
	return vnic && !self && !(vf && local_intf && local_pf);
}
#endif

int efx_ef100_lookup_client_id(struct efx_nic *efx, efx_qword_t pciefn, u32 *id)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_CLIENT_HANDLE_OUT_LEN);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_GET_CLIENT_HANDLE_IN_LEN);
	u64 pciefn_flat = le64_to_cpu(pciefn.u64[0]);
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, GET_CLIENT_HANDLE_IN_TYPE,
		       MC_CMD_GET_CLIENT_HANDLE_IN_TYPE_FUNC);
	MCDI_SET_QWORD(inbuf, GET_CLIENT_HANDLE_IN_FUNC,
		       pciefn_flat);

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_CLIENT_HANDLE, inbuf,
			  sizeof(inbuf), outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	*id = MCDI_DWORD(outbuf, GET_CLIENT_HANDLE_OUT_HANDLE);
	return 0;
}

int ef100_probe_netdev_pf(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
	struct net_device *net_dev = efx->net_dev;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
	unsigned int nreps = 0;
	unsigned int rep_idx;
	unsigned int i;
#endif
	int rc;

	if (!nic_data->grp_mae)
		return 0;

	rc = efx_ef100_get_base_mport(efx);
	if (rc)
		netif_warn(efx, probe, net_dev,
			   "Failed to probe base mport rc %d; representors will not function\n",
			   rc);

	rc = efx_init_tc(efx);
	if (rc) {
		/* Either we don't have an MAE at all (i.e. legacy v-switching),
		 * or we do but we failed to probe it.  In the latter case, we
		 * may not have set up default rules, in which case we won't be
		 * able to pass any traffic.  However, we don't fail the probe,
		 * because the user might need to use the netdevice to apply
		 * configuration changes to fix whatever's wrong with the MAE.
		 */
		netif_warn(efx, probe, net_dev,
			   "Failed to probe MAE rc %d; TC offload unavailable\n",
			   rc);
	} else {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
		net_dev->features |= NETIF_F_HW_TC;
		efx->fixed_features |= NETIF_F_HW_TC;
#endif
	}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
	nic_data->have_local_intf = false;
	for (i = 0; i < efx->tc->n_mports; i++)
		if (nic_data->have_old_mport &&
		    efx->tc->mports[i].mport_id == nic_data->old_base_mport) {
			WARN_ON(efx->tc->mports[i].mport_type !=
				MAE_MPORT_DESC_MPORT_TYPE_VNIC);
			WARN_ON(efx->tc->mports[i].vnic_client_type !=
				MAE_MPORT_DESC_VNIC_CLIENT_TYPE_FUNCTION);
			nic_data->local_mae_intf = efx->tc->mports[i].interface_idx;
			nic_data->have_local_intf = true;
			netif_dbg(efx, probe, net_dev,
				  "MAE interface_idx is %u\n",
				  nic_data->local_mae_intf);
			break;
		}
	if (!nic_data->have_local_intf)
		netif_warn(efx, probe, net_dev,
			   "Own m-port desc not found; using remote_reps for local VFs\n");
	for (i = 0; i < efx->tc->n_mports; i++) {
		if (ef100_mport_needs_rep(efx, &efx->tc->mports[i]))
			nreps++;
	}
	if (!nreps)
		return 0;
	nic_data->rem_rep = kcalloc(nreps,
				    sizeof(struct net_device *),
				    GFP_KERNEL);
	if (!nic_data->rem_rep) {
		netif_warn(efx, probe, net_dev,
			   "Failed to allocate memory for remote_reps\n");
		return 0;
	}

	for (i = 0; i < efx->tc->n_mports; i++) {
		if (!ef100_mport_needs_rep(efx, &efx->tc->mports[i]))
			continue;
		if (WARN_ON(nic_data->rem_rep_count >= nreps))
			return 0;
		/* increment rem_rep_count early, as it is used in
		 * ef100_get_remote_rep called in the stack of
		 * efx_ef100_remote_rep_create */
		rep_idx = nic_data->rem_rep_count++;
		rc = efx_ef100_remote_rep_create(efx, rep_idx, i);
		if (rc) {
			nic_data->rem_rep_count--;
			netif_warn(efx, probe, net_dev,
				   "Failed to create a remote_rep, rc %d\n",
				   rc);
			return 0;
		}
	}
#endif

	return 0;
}

int ef100_probe_vf(struct efx_nic *efx)
{
	BUILD_BUG_ON(MAE_MPORT_SELECTOR_NULL);

	return ef100_probe_main(efx);
}

void ef100_remove(struct efx_nic *efx)
{
	struct ef100_nic_data *nic_data = efx->nic_data;
#if defined(CONFIG_SFC_VDPA)
	struct efx_probe_data *probe_data;

	if (nic_data && (nic_data->bar_config == EF100_BAR_CONFIG_VDPA)) {
		probe_data = container_of(efx, struct efx_probe_data, efx);
		ef100_vdpa_fini(probe_data);
	}
#endif

	device_remove_file(&efx->pci_dev->dev, &dev_attr_bar_config);
	efx_remove_common(efx);
	if (nic_data) {
		if (efx->mcdi_buf_mode == EFX_BUF_MODE_EF100)
			efx_nic_free_buffer(efx, &nic_data->mcdi_buf);
#if defined(CONFIG_SFC_VDPA)
		else
			ef100_vdpa_free_buffer(efx->vdpa_nic,
					       &nic_data->mcdi_buf);
		mutex_destroy(&nic_data->bar_config_lock);
#endif
	}

	kfree(nic_data);
	efx->nic_data = NULL;
}

/*	NIC level access functions
 */
#ifdef EFX_C_MODEL
#define EF100_OFFLOAD_FEATURES	(NETIF_F_HW_CSUM | NETIF_F_RXCSUM |	\
	NETIF_F_HIGHDMA | NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_NTUPLE | \
	NETIF_F_RXHASH | NETIF_F_RXFCS | NETIF_F_TSO_ECN | NETIF_F_RXALL | \
	NETIF_F_HW_VLAN_CTAG_TX)
#else
#define EF100_OFFLOAD_FEATURES	(NETIF_F_HW_CSUM | NETIF_F_RXCSUM |	\
	NETIF_F_HIGHDMA | NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_NTUPLE | \
	NETIF_F_RXHASH | NETIF_F_RXFCS | NETIF_F_TSO_ECN | NETIF_F_RXALL | \
	NETIF_F_HW_VLAN_CTAG_TX)
#endif

const struct efx_nic_type ef100_pf_nic_type = {
	.revision = EFX_REV_EF100,
	.is_vf = false,
	.probe = ef100_probe_main,
	.net_alloc = ef100_net_alloc,
	.net_dealloc = ef100_net_dealloc,
	.offload_features = EF100_OFFLOAD_FEATURES,
	.mcdi_max_ver = 2,
	.mcdi_rpc_timeout = efx_ef100_mcdi_rpc_timeout,
	.mcdi_request = ef100_mcdi_request,
	.mcdi_poll_response = ef100_mcdi_poll_response,
	.mcdi_read_response = ef100_mcdi_read_response,
	.mcdi_poll_reboot = ef100_mcdi_poll_reboot,
	.mcdi_get_buf = ef100_mcdi_get_buf,
	.mcdi_put_buf = ef100_mcdi_put_buf,
	.mcdi_reboot_detected = ef100_mcdi_reboot_detected,
	.irq_enable_master = efx_port_dummy_op_void,
	.irq_test_generate = efx_ef100_irq_test_generate,
	.irq_disable_non_ev = efx_port_dummy_op_void,
	.push_irq_moderation = efx_channel_dummy_op_void,
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_BUSYPOLL)
	.supported_interrupt_modes = BIT(EFX_INT_MODE_MSIX) |
				     BIT(EFX_INT_MODE_POLLED),
#else
	.supported_interrupt_modes = BIT(EFX_INT_MODE_MSIX),
#endif
	.map_reset_reason = ef100_map_reset_reason,
	.map_reset_flags = ef100_map_reset_flags,
	.reset = ef100_reset,

	.check_caps = ef100_check_caps,

	.ev_probe = ef100_ev_probe,
	.ev_init = ef100_ev_init,
	.ev_fini = efx_mcdi_ev_fini,
	.ev_remove = efx_mcdi_ev_remove,
	.irq_handle_msi = ef100_msi_interrupt,
	.ev_process = ef100_ev_process,
	.ev_mcdi_pending = ef100_ev_mcdi_pending,
	.ev_read_ack = ef100_ev_read_ack,
	.ev_test_generate = efx_ef100_ev_test_generate,
	.tx_probe = ef100_tx_probe,
	.tx_init = ef100_tx_init,
	.tx_write = ef100_tx_write,
	.tx_notify = ef100_notify_tx_desc,
	.tx_enqueue = ef100_enqueue_skb,
	.tx_max_skb_descs = ef100_tx_max_skb_descs,
	.rx_set_rss_flags = efx_mcdi_set_rss_context_flags,
	.rx_get_rss_flags = efx_mcdi_get_rss_context_flags,
	.rx_probe = ef100_rx_probe,
	.rx_init = ef100_rx_init,
	.rx_remove = efx_mcdi_rx_remove,
	.rx_write = ef100_rx_write,
	.rx_defer_refill = efx_ef100_rx_defer_refill,
	.rx_packet = __ef100_rx_packet,
	.rx_buf_hash_valid = ef100_rx_buf_hash_valid,
	.max_rx_ip_filters = EFX_MCDI_FILTER_TBL_ROWS,
	.set_id_led = efx_mcdi_set_id_led,
	.filter_table_probe = ef100_filter_table_init,
	.filter_table_up = ef100_filter_table_up,
	.filter_table_restore = efx_mcdi_filter_table_restore,
	.filter_table_down = ef100_filter_table_down,
	.filter_table_remove = efx_mcdi_filter_table_fini,
	.filter_insert = efx_mcdi_filter_insert,
	.filter_remove_safe = efx_mcdi_filter_remove_safe,
	.filter_get_safe = efx_mcdi_filter_get_safe,
	.filter_clear_rx = efx_mcdi_filter_clear_rx,
	.filter_count_rx_used = efx_mcdi_filter_count_rx_used,
	.filter_get_rx_id_limit = efx_mcdi_filter_get_rx_id_limit,
	.filter_get_rx_ids = efx_mcdi_filter_get_rx_ids,
#ifdef EFX_NOT_UPSTREAM
	.filter_redirect = efx_mcdi_filter_redirect,
#ifdef CONFIG_SFC_DRIVERLINK
	.filter_block_kernel = efx_mcdi_filter_block_kernel,
	.filter_unblock_kernel = efx_mcdi_filter_unblock_kernel,
	.regionmap_buffer = ef100_regionmap_buffer,
#endif
#endif
#ifdef CONFIG_RFS_ACCEL
	.filter_rfs_expire_one = efx_mcdi_filter_rfs_expire_one,
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_VLAN_RX_ADD_VID)
	.vlan_rx_add_vid = efx_mcdi_filter_add_vid,
	.vlan_rx_kill_vid = efx_mcdi_filter_del_vid,
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_NEED_GET_PHYS_PORT_ID)
	.get_phys_port_id = efx_ef100_get_phys_port_id,
#endif

	.rx_prefix_size = ESE_GZ_RX_PKT_PREFIX_LEN,
	.rx_hash_offset = ESF_GZ_RX_PREFIX_RSS_HASH_LBN / 8,
	.rx_ts_offset = ESF_GZ_RX_PREFIX_PARTIAL_TSTAMP_LBN / 8,
	.rx_hash_key_size = 40,
	.rx_pull_rss_config = efx_mcdi_rx_pull_rss_config,
	.rx_push_rss_config = efx_mcdi_pf_rx_push_rss_config,
	.rx_push_rss_context_config = efx_mcdi_rx_push_rss_context_config,
	.rx_pull_rss_context_config = efx_mcdi_rx_pull_rss_context_config,
	.rx_restore_rss_contexts = efx_mcdi_rx_restore_rss_contexts,

	.reconfigure_mac = ef100_reconfigure_mac,
	.reconfigure_port = efx_mcdi_port_reconfigure,
	.test_nvram = efx_mcdi_nvram_test_all,
	.describe_stats = ef100_describe_stats,
	.update_stats = ef100_update_stats,
	.pull_stats = ef100_pull_stats,
	.has_dynamic_sensors = ef100_has_dynamic_sensors,

	/* Per-type bar/size configuration not used on ef100. Location of
	 * registers is defined by extended capabilities.
	 */
	.mem_bar = NULL,
	.mem_map_size = NULL,
	.max_dma_mask = DMA_BIT_MASK(ESF_GZ_TX_SEND_ADDR_WIDTH),

#if defined(EFX_USE_KCOMPAT) && defined(EFX_TC_OFFLOAD) && !defined(EFX_HAVE_FLOW_INDR_BLOCK_CB_REGISTER) && !defined(EFX_HAVE_FLOW_INDR_DEV_REGISTER)
	.udp_tnl_add_port2 = efx_ef100_udp_tnl_add_port,
	.udp_tnl_lookup_port2 = efx_ef100_udp_tnl_lookup_port,
	.udp_tnl_del_port2 = efx_ef100_udp_tnl_del_port,
#endif

#if defined(CONFIG_SFC_SRIOV)
	.sriov_configure = efx_ef100_sriov_configure,
#endif
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_TC_OFFLOAD)
	.get_vf_rep = ef100_get_vf_rep,
	.get_remote_rep = ef100_get_remote_rep,
	.detach_reps = ef100_detach_reps,
	.attach_reps = ef100_attach_reps,
#endif

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	.ef10_resources = {
		.hdr.type = EFX_DL_EF10_RESOURCES,
	},
#endif
#endif
};

const struct efx_nic_type ef100_vf_nic_type = {
	.revision = EFX_REV_EF100,
	.is_vf = true,
	.probe = ef100_probe_vf,
	.net_alloc = ef100_net_alloc,
	.net_dealloc = ef100_net_dealloc,
	.offload_features = EF100_OFFLOAD_FEATURES,
	.mcdi_max_ver = 2,
	.mcdi_rpc_timeout = efx_ef100_mcdi_rpc_timeout,
	.mcdi_request = ef100_mcdi_request,
	.mcdi_poll_response = ef100_mcdi_poll_response,
	.mcdi_read_response = ef100_mcdi_read_response,
	.mcdi_poll_reboot = ef100_mcdi_poll_reboot,
	.mcdi_get_buf = ef100_mcdi_get_buf,
	.mcdi_put_buf = ef100_mcdi_put_buf,
	.mcdi_reboot_detected = ef100_mcdi_reboot_detected,
	.irq_enable_master = efx_port_dummy_op_void,
	.irq_test_generate = efx_ef100_irq_test_generate,
	.irq_disable_non_ev = efx_port_dummy_op_void,
	.push_irq_moderation = efx_channel_dummy_op_void,
#if defined(EFX_NOT_UPSTREAM) && defined(CONFIG_SFC_BUSYPOLL)
	.supported_interrupt_modes = BIT(EFX_INT_MODE_MSIX) |
				     BIT(EFX_INT_MODE_POLLED),
#else
	.supported_interrupt_modes = BIT(EFX_INT_MODE_MSIX),
#endif
	.map_reset_reason = ef100_map_reset_reason,
	.map_reset_flags = ef100_map_reset_flags,
	.reset = ef100_reset,
	.check_caps = ef100_check_caps,
	.ev_probe = ef100_ev_probe,
	.ev_init = ef100_ev_init,
	.ev_fini = efx_mcdi_ev_fini,
	.ev_remove = efx_mcdi_ev_remove,
	.irq_handle_msi = ef100_msi_interrupt,
	.ev_process = ef100_ev_process,
	.ev_mcdi_pending = ef100_ev_mcdi_pending,
	.ev_read_ack = ef100_ev_read_ack,
	.ev_test_generate = efx_ef100_ev_test_generate,
	.tx_probe = ef100_tx_probe,
	.tx_init = ef100_tx_init,
	.tx_write = ef100_tx_write,
	.tx_notify = ef100_notify_tx_desc,
	.tx_enqueue = ef100_enqueue_skb,
	.tx_max_skb_descs = ef100_tx_max_skb_descs,
	.rx_set_rss_flags = efx_mcdi_set_rss_context_flags,
	.rx_get_rss_flags = efx_mcdi_get_rss_context_flags,
	.rx_probe = ef100_rx_probe,
	.rx_init = ef100_rx_init,
	.rx_remove = efx_mcdi_rx_remove,
	.rx_write = ef100_rx_write,
	.rx_defer_refill = efx_ef100_rx_defer_refill,
	.rx_packet = __ef100_rx_packet,
	.max_rx_ip_filters = EFX_MCDI_FILTER_TBL_ROWS,
	.filter_table_probe = ef100_filter_table_init,
	.filter_table_up = ef100_filter_table_up,
	.filter_table_restore = efx_mcdi_filter_table_restore,
	.filter_table_down = ef100_filter_table_down,
	.filter_table_remove = efx_mcdi_filter_table_fini,
	.filter_insert = efx_mcdi_filter_insert,
	.filter_remove_safe = efx_mcdi_filter_remove_safe,
	.filter_get_safe = efx_mcdi_filter_get_safe,
	.filter_clear_rx = efx_mcdi_filter_clear_rx,
	.filter_count_rx_used = efx_mcdi_filter_count_rx_used,
	.filter_get_rx_id_limit = efx_mcdi_filter_get_rx_id_limit,
	.filter_get_rx_ids = efx_mcdi_filter_get_rx_ids,
#ifdef EFX_NOT_UPSTREAM
	.filter_redirect = efx_mcdi_filter_redirect,
#ifdef CONFIG_SFC_DRIVERLINK
	.filter_block_kernel = efx_mcdi_filter_block_kernel,
	.filter_unblock_kernel = efx_mcdi_filter_unblock_kernel,
	.regionmap_buffer = ef100_regionmap_buffer,
#endif
#endif
#ifdef CONFIG_RFS_ACCEL
	.filter_rfs_expire_one = efx_mcdi_filter_rfs_expire_one,
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_VLAN_RX_ADD_VID)
	.vlan_rx_add_vid = efx_mcdi_filter_add_vid,
	.vlan_rx_kill_vid = efx_mcdi_filter_del_vid,
#endif

	.rx_prefix_size = ESE_GZ_RX_PKT_PREFIX_LEN,
	.rx_hash_offset = ESF_GZ_RX_PREFIX_RSS_HASH_LBN / 8,
	.rx_ts_offset = ESF_GZ_RX_PREFIX_PARTIAL_TSTAMP_LBN / 8,
	.rx_hash_key_size = 40,
	.rx_pull_rss_config = efx_mcdi_rx_pull_rss_config,
	.rx_push_rss_config = efx_mcdi_pf_rx_push_rss_config,
	.rx_restore_rss_contexts = efx_mcdi_rx_restore_rss_contexts,

	.reconfigure_mac = ef100_reconfigure_mac,
	.test_nvram = efx_mcdi_nvram_test_all,
	.describe_stats = ef100_describe_stats,
	.update_stats = ef100_update_stats,
	.pull_stats = ef100_pull_stats,
	.has_dynamic_sensors = ef100_has_dynamic_sensors,

	.mem_bar = NULL,
	.mem_map_size = NULL,
	.max_dma_mask = DMA_BIT_MASK(ESF_GZ_TX_SEND_ADDR_WIDTH),
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	.ef10_resources = {
		.hdr.type = EFX_DL_EF10_RESOURCES,
	},
#endif
#endif
};
