/* SPDX-License-Identifier: GPL-2.0-only */
/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2013 Solarflare Communications Inc.
 * Copyright 2019-2022 Xilinx Inc.
 */

#ifndef EFX_NIC_COMMON_H
#define EFX_NIC_COMMON_H

#include "net_driver.h"
#include "efx_common.h"
#include "mcdi.h"
#include "ptp.h"

enum {
	/* Revisions 0-2 were Falcon A0, A1 and B0 respectively.
	 * They are not supported by this driver but these revision numbers
	 * form part of the ethtool API for register dumping.
	 */
	EFX_REV_SIENA_A0 = 3,
	EFX_REV_HUNT_A0 = 4,
	EFX_REV_EF100 = 5,
};

static inline int efx_nic_rev(struct efx_nic *efx)
{
	return efx->type->revision;
}

/* Read the current event from the event queue */
static inline efx_qword_t *efx_event(struct efx_channel *channel,
				     unsigned int index)
{
	return ((efx_qword_t *) (channel->eventq.addr)) +
		(index & channel->eventq_mask);
}

/* See if an event is present
 *
 * We check both the high and low dword of the event for all ones.  We
 * wrote all ones when we cleared the event, and no valid event can
 * have all ones in either its high or low dwords.  This approach is
 * robust against reordering.
 *
 * Note that using a single 64-bit comparison is incorrect; even
 * though the CPU read will be atomic, the DMA write may not be.
 */
static inline int efx_event_present(efx_qword_t *event)
{
	return !(EFX_DWORD_IS_ALL_ONES(event->dword[0]) |
		  EFX_DWORD_IS_ALL_ONES(event->dword[1]));
}

/* Returns a pointer to the specified transmit descriptor in the TX
 * descriptor queue belonging to the specified channel.
 */
static inline efx_qword_t *
efx_tx_desc(struct efx_tx_queue *tx_queue, unsigned int index)
{
	return ((efx_qword_t *) (tx_queue->txd.addr)) + index;
}

/* Report whether this TX queue would be empty for the given write_count.
 * May return false negative.
 */
static inline bool __efx_nic_tx_is_empty(struct efx_tx_queue *tx_queue,
					 unsigned int write_count)
{
	unsigned int empty_read_count = READ_ONCE(tx_queue->empty_read_count);

	if (empty_read_count == 0)
		return false;

	return ((empty_read_count ^ write_count) & ~EFX_EMPTY_COUNT_VALID) == 0;
}

/* Report whether the NIC considers this TX queue empty, using
 * packet_write_count (the write count recorded for the last completable
 * doorbell push).  May return false negative.  EF10 only, which is OK
 * because only EF10 supports PIO.
 */
static inline bool efx_nic_tx_is_empty(struct efx_tx_queue *tx_queue)
{
	EFX_WARN_ON_ONCE_PARANOID(!tx_queue->efx->type->option_descriptors);
	return __efx_nic_tx_is_empty(tx_queue, tx_queue->packet_write_count);
}

/* Decide whether to push a TX descriptor to the NIC vs merely writing
 * the doorbell.  This can reduce latency when we are adding a single
 * descriptor to an empty queue, but is otherwise pointless.  Further,
 * Falcon and Siena have hardware bugs (SF bug 33851) that may be
 * triggered if we don't check this.
 * We use the write_count used for the last doorbell push, to get the
 * NIC's view of the tx queue.
 */
static inline bool efx_nic_may_push_tx_desc(struct efx_tx_queue *tx_queue,
					    unsigned int write_count)
{
	bool was_empty = __efx_nic_tx_is_empty(tx_queue, write_count);

	tx_queue->empty_read_count = 0;
	return was_empty && tx_queue->write_count - write_count == 1;
}

/* Returns a pointer to the specified descriptor in the RX descriptor queue */
static inline efx_qword_t *
efx_rx_desc(struct efx_rx_queue *rx_queue, unsigned int index)
{
	return ((efx_qword_t *) (rx_queue->rxd.addr)) + index;
}

/* Alignment of PCIe DMA boundaries (4KB) */
#define EFX_PAGE_SIZE	4096
/* Size and alignment of buffer table entries (same) */
#define EFX_BUF_SIZE	EFX_PAGE_SIZE

/* NIC-generic software stats */
enum {
	GENERIC_STAT_rx_noskb_drops,
	GENERIC_STAT_rx_nodesc_trunc,
	GENERIC_STAT_COUNT
};

#define EFX_GENERIC_SW_STAT(ext_name)				\
	[GENERIC_STAT_ ## ext_name] = { #ext_name, 0, 0 }

/* TX data path */
static inline int efx_nic_probe_tx(struct efx_tx_queue *tx_queue)
{
	return tx_queue->efx->type->tx_probe(tx_queue);
}
static inline int efx_nic_init_tx(struct efx_tx_queue *tx_queue)
{
	return tx_queue->efx->type->tx_init(tx_queue);
}
static inline void efx_nic_push_buffers(struct efx_tx_queue *tx_queue)
{
	tx_queue->efx->type->tx_write(tx_queue);
}
static inline void efx_nic_notify_tx_desc(struct efx_tx_queue *tx_queue)
{
	tx_queue->efx->type->tx_notify(tx_queue);
}
int efx_nic_tx_tso_sw(struct efx_tx_queue *tx_queue, struct sk_buff *skb,
		      bool *data_mapped);

/* RX data path */
static inline int efx_nic_probe_rx(struct efx_rx_queue *rx_queue)
{
	return rx_queue->efx->type->rx_probe(rx_queue);
}
static inline int efx_nic_init_rx(struct efx_rx_queue *rx_queue)
{
	return rx_queue->efx->type->rx_init(rx_queue);
}
static inline void efx_nic_remove_rx(struct efx_rx_queue *rx_queue)
{
	rx_queue->efx->type->rx_remove(rx_queue);
}
static inline void efx_nic_notify_rx_desc(struct efx_rx_queue *rx_queue)
{
	rx_queue->efx->type->rx_write(rx_queue);
}
static inline int efx_nic_generate_fill_event(struct efx_rx_queue *rx_queue)
{
	return rx_queue->efx->type->rx_defer_refill(rx_queue);
}

/* Event data path */
static inline int efx_nic_probe_eventq(struct efx_channel *channel)
{
	return channel->efx->type->ev_probe(channel);
}
static inline int efx_nic_init_eventq(struct efx_channel *channel)
{
	return channel->efx->type->ev_init(channel);
}
static inline void efx_nic_fini_eventq(struct efx_channel *channel)
{
	channel->efx->type->ev_fini(channel);
}
static inline void efx_nic_remove_eventq(struct efx_channel *channel)
{
	channel->efx->type->ev_remove(channel);
}
static inline int
efx_nic_process_eventq(struct efx_channel *channel, int quota)
{
	return channel->efx->type->ev_process(channel, quota);
}
static inline bool efx_nic_mcdi_ev_pending(struct efx_channel *channel)
{
	return channel->efx->type->ev_mcdi_pending(channel);
}
static inline void efx_nic_eventq_read_ack(struct efx_channel *channel)
{
	channel->efx->type->ev_read_ack(channel);
}

static inline bool efx_nic_hw_unavailable(struct efx_nic *efx)
{
	if (efx->type->hw_unavailable)
		return efx->type->hw_unavailable(efx);
	return false;
}
static inline bool efx_nic_has_dynamic_sensors(struct efx_nic *efx)
{
	if (efx->type->has_dynamic_sensors)
		return efx->type->has_dynamic_sensors(efx);

	return false;
}

void efx_nic_event_test_start(struct efx_channel *channel);
bool efx_nic_event_present(struct efx_channel *channel);

static inline unsigned int efx_rx_recycle_ring_size(const struct efx_nic *efx)
{
	return efx->type->rx_recycle_ring_size(efx);
}

/* Some statistics are computed as A - B where A and B each increase
 * linearly with some hardware counter(s) and the counters are read
 * asynchronously.  If the counters contributing to B are always read
 * after those contributing to A, the computed value may be lower than
 * the true value by some variable amount, and may decrease between
 * subsequent computations.
 *
 * We should never allow statistics to decrease or to exceed the true
 * value.  Since the computed value will never be greater than the
 * true value, except when the MAC stats are zeroed as a result of a NIC reset
 * we can achieve this by only storing the computed value
 * when it increases, or when it is zeroed.
 */
static inline void efx_update_diff_stat(u64 *stat, u64 diff)
{
	if (!diff || (s64)(diff - *stat) > 0)
		*stat = diff;
}

/* Interrupts */
int efx_nic_init_interrupt(struct efx_nic *efx);
int efx_nic_irq_test_start(struct efx_nic *efx);
void efx_nic_fini_interrupt(struct efx_nic *efx);

static inline int efx_nic_event_test_irq_cpu(struct efx_channel *channel)
{
	return READ_ONCE(channel->event_test_cpu);
}
static inline int efx_nic_irq_test_irq_cpu(struct efx_nic *efx)
{
	return READ_ONCE(efx->last_irq_cpu);
}

/* Global Resources */
void efx_nic_check_pcie_link(struct efx_nic *efx,
			     unsigned int desired_bandwidth,
			     unsigned int *actual_width,
			     unsigned int *actual_speed);

int efx_nic_alloc_buffer(struct efx_nic *efx, struct efx_buffer *buffer,
			 unsigned int len, gfp_t gfp_flags);
void efx_nic_free_buffer(struct efx_nic *efx, struct efx_buffer *buffer);

size_t efx_nic_get_regs_len(struct efx_nic *efx);
void efx_nic_get_regs(struct efx_nic *efx, void *buf);

#define EFX_MC_STATS_GENERATION_INVALID ((__force __le64)(-1))

size_t efx_nic_describe_stats(const struct efx_hw_stat_desc *desc, size_t count,
			      const unsigned long *mask, u8 *names);
int efx_nic_copy_stats(struct efx_nic *efx, __le64 *dest);
static inline int efx_nic_reset_stats(struct efx_nic *efx)
{
	return efx_nic_copy_stats(efx, efx->mc_initial_stats);
}
void efx_nic_update_stats(const struct efx_hw_stat_desc *desc, size_t count,
			  const unsigned long *mask, u64 *stats,
			  const void *mc_initial_stats, const void *mc_stats);
void efx_nic_fix_nodesc_drop_stat(struct efx_nic *efx, u64 *stat);

#ifdef EFX_NOT_UPSTREAM
static inline
bool efx_nic_client_supported(struct efx_nic *efx, enum efx_client_type type)
{
	if (efx->type->client_supported)
		return efx->type->client_supported(efx, type);
	/* Legacy NICs support an ethernet device and Onload stacks */
	return (type == EFX_CLIENT_ETH || type == EFX_CLIENT_ONLOAD);
}
#endif

#define EFX_MAX_FLUSH_TIME 5000

bool efx_mcdi_port_process_event(struct efx_channel *channel, efx_qword_t *event,
				 int *rc, int budget);

#endif /* EFX_NIC_COMMON_H */
