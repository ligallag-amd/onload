/* SPDX-License-Identifier: GPL-2.0 */
/*
 * efx_auxbus.h - Solarflare auxiliary bus interface
 *
 * Copyright 2023-2024, Advanced Micro Devices, Inc.
 */
#ifndef _EFX_AUXBUS_H
#define _EFX_AUXBUS_H

#ifdef EFX_NOT_UPSTREAM
/* This is part of the device name exposed in the auxiliary bus. */
#define EFX_ONLOAD_DEVNAME	"onload"
#endif

/* Driver API */
/**
 * enum efx_auxdev_event_type - Events a driver can get.
 *
 * @EFX_AUXDEV_EVENT_IN_RESET: Hardware is resetting.
 * @EFX_AUXDEV_EVENT_LINK_CHANGE: Physical link has changed state.
 */
enum efx_auxdev_event_type {
	EFX_AUXDEV_EVENT_IN_RESET,
	EFX_AUXDEV_EVENT_LINK_CHANGE,
};

#define EFX_AUXDEV_ALL_EVENTS	(BIT(EFX_AUXDEV_EVENT_IN_RESET) | \
				 BIT(EFX_AUXDEV_EVENT_LINK_CHANGE))

struct efx_auxdev_event {
	enum efx_auxdev_event_type	type;
	bool				value;	/* Link or reset state. */
};

struct efx_auxdev_client;
typedef void (efx_auxdev_event_handler)(struct efx_auxdev_client *,
					const struct efx_auxdev_event *);
struct efx_auxdev;

/**
 * struct efx_design_params - Design parameters.
 *
 * @rx_stride: stride between entries in receive window.
 * @rx_buffer_len: Length of each receive buffer.
 * @rx_queues: Maximum Rx queues available.
 * @tx_apertures: Maximum Tx apertures available.
 * @rx_buf_fifo_size: Maximum number of receive buffers can be posted.
 * @frame_offset_fixed: Fixed offset to the frame.
 * @rx_metadata_len: Receive metadata length.
 * @tx_max_reorder: Largest window of reordered writes to the CTPIO.
 * @tx_aperture_size: CTPIO aperture length.
 * @tx_fifo_size: Size of packet FIFO per CTPIO aperture.
 * @ts_subnano_bit: partial time stamp in sub nano seconds.
 * @unsol_credit_seq_mask: Width of sequence number in EVQ_UNSOL_CREDIT_GRANT
 *	register.
 * @l4_csum_proto: L4 csm feilds.
 * @max_runt: MAx length of frame data when LEN_ERR indicates runt.
 * @evq_sizes: Event queue sizes.
 * @num_filter: Number of filters.
 */
struct efx_design_params {
	u32 rx_stride;
	u32 rx_buffer_len;
	u32 rx_queues;
	u32 tx_apertures;
	u32 rx_buf_fifo_size;
	u32 frame_offset_fixed;
	u32 rx_metadata_len;
	u32 tx_max_reorder;
	u32 tx_aperture_size;
	u32 tx_fifo_size;
	u32 ts_subnano_bit;
	u32 unsol_credit_seq_mask;
	u32 l4_csum_proto;
	u32 max_runt;
	u32 evq_sizes;
	u32 num_filter;
};

/**
 * struct efx_auxdev_client - Information for attached drivers.
 *
 * This is also used for device operations.
 *
 * @auxdev: Auxiliary device in use.
 * @event_handler: Driver callback for device events.
 * @events_requested: Bitmap of events reported to the driver.
 * @client_id: Unique identifier to manage resources for this client.
 * @driver_data: For private use by the attached driver.
 * @net_dev: Optional, set if the client's parent has a network device.
 * @channels: All channels allocated to this client. Each entry is a pointer to
 *	a struct efx_client_channel.
 * @membase_addr: Kernel virtual address of the start of the memory BAR.
 * @design_params: Hardware design parameters.
 * @use_msi: %true if the hardware uses an MSI interrupt. Only set if MSI-X
 *	is not supported.
 */
struct efx_auxdev_client {
	struct efx_auxdev *auxdev;
	efx_auxdev_event_handler *event_handler;
	unsigned int events_requested;
	u32 client_id;
	void *driver_data;
	struct net_device *net_dev;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XARRAY)
	struct xarray channels;
#endif
	resource_size_t *membase_addr;
	struct efx_design_params design_params;
	bool use_msi;
};

/* Device API */

/**
 * struct efx_auxdev_rpc - Remote Procedure Call to the firmware.
 *
 * @cmd: MCDI command to perform.
 * @inlen: Size of @inbuf, in bytes.
 * @inbuf: Input parameters to the MCDI command. This may be %NULL if @inlen
 *	is 0.
 * @outlen: Size of @outbuf (provided by the caller), in bytes.
 * @outlen_actual: The number of bytes in @outbuf that have been populated by
 *	the firmware. On older firmware this could be less than @outlen, so
 *	output beyond @outlen_actual must not be used. This may be %NULL if
 *	@outlen is 0.
 * @outbuf: Output results from the MCDI command. This buffer must be provided
 *	by the caller. This may be %NULL if @outlen is 0.
 */
struct efx_auxdev_rpc {
	unsigned int cmd;
	size_t inlen;
	const u32 *inbuf;
	size_t outlen;
	size_t outlen_actual;
	u32 *outbuf;
};

#ifdef EFX_NOT_UPSTREAM
/* Defined in filter.h */
struct efx_filter_spec;

/**
 * struct efx_auxdev_dl_vi_resources - Driverlink VI information
 *
 * @vi_base: Absolute index of first VI in this function.  This may change
 *	after a reset.  Clients that cache this value will need to update
 *	the cached value in their reset_resume() function.
 * @vi_min: Relative index of first available VI
 * @vi_lim: Relative index of last available VI + 1
 * @rss_channel_count: Number of receive channels used for RSS.
 * @vi_shift: Shift value for absolute VI number computation.
 * @vi_stride: size in bytes of a single VI.
 * @mem_bar: PCIe memory BAR index.
 * @pci_dev: The PCI device.
 */
struct efx_auxdev_dl_vi_resources {
	unsigned int vi_base;
	unsigned int vi_min;
	unsigned int vi_lim;
	unsigned int rss_channel_count;
	unsigned int vi_shift;
	unsigned int vi_stride;
	unsigned int mem_bar;
	struct pci_dev *pci_dev;
};

/**
 * enum efx_auxiliary_param - Device parameters
 *
 * @EFX_NETDEV: Optional, set if the client's parent has an ethernet device.
 *	Get only.
 *	Returned through @net_dev.
 * @EFX_MEMBASE: Kernel virtual address of the start of the memory BAR.
 *	Get only.
 *	Returned through @membase_addr.
 * @EFX_USE_MSI: Hardware only has an MSI interrupt, no MSI-X.
 *	Get only.
 *	Returned through @b.
 * @EFX_CHANNELS: All channels allocated to this client. Each entry is a
 *	pointer to a struct efx_client_channel. Get only.
 *	Returned through @channels.
 * @EFX_RXFH_DEFAULT_FLAGS: Default RSS flags. Get only.
 *	Returned through @value.
 * @EFX_DESIGN_PARAM: Hardware design parameters. Get only.
 *	Returned through @design_params.
 * @EFX_PCI_DEVICE: The underlying PCI device, as `pci_dev->device`. Get only.
 *	Value passed via @value.
 * @EFX_DEVICE_REVISION: Device revision. Get only. Value passed via @value.
 * @EFX_TIMER_QUANTUM_NS: Timer quantum (nominal period between timer ticks)
 *      for wakeup timers, in nanoseconds. Get only.
 *      Value passed via @value.
 * @EFX_DRIVER_DATA: Private data used by the attached driver. Get or set.
 *	Returned through @driver_data.
 * @EFX_PARAM_FILTER_BLOCK_KERNEL_UCAST: Block unicast traffic. Get or set.
 *	Value passed via @b.
 * @EFX_PARAM_FILTER_BLOCK_KERNEL_MCAST: Block multicast traffic. Get or set.
 *	Value passed via @b.
 */
enum efx_auxiliary_param {
	EFX_NETDEV,
	EFX_MEMBASE,
	EFX_USE_MSI,
	EFX_CHANNELS,
	EFX_RXFH_DEFAULT_FLAGS,
	EFX_DESIGN_PARAM,
	EFX_PCI_DEVICE,
	EFX_DEVICE_REVISION,
	EFX_TIMER_QUANTUM_NS,
	EFX_DRIVER_DATA,
	EFX_PARAM_FILTER_BLOCK_KERNEL_UCAST,
	EFX_PARAM_FILTER_BLOCK_KERNEL_MCAST,
};

/** Possible values for device parameters */
union efx_auxiliary_param_value {
	struct net_device *net_dev;
	resource_size_t *membase_addr;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XARRAY)
	struct xarray channels;
#endif
	int value;
	bool b;
	struct efx_design_params *design_params;
	void *driver_data;
};
#endif

/**
 * struct efx_auxdev_ops - Device operations.
 *
 * @open: Clients need to open a device before using it. This allocates a
 *	client ID used for further operations, and can register a callback
 *	function for events. events_requested is a bitmap of
 *	enum efx_event_type.
 *	Returns an error pointer for a failure.
 * @close: Closing a device stops it from getting events and frees client
 *	resources.
 * @fw_rpc: Remote procedure call to the firmware. Returns a negative error
 *	code or 0 on success.
 */
struct efx_auxdev_ops {
	struct efx_auxdev_client *(*open)(struct auxiliary_device *auxdev,
					  efx_auxdev_event_handler *func,
					  unsigned int events_requested);
	void (*close)(struct efx_auxdev_client *handle);

	int (*fw_rpc)(struct efx_auxdev_client *handle,
		      struct efx_auxdev_rpc *rpc);

#ifdef EFX_NOT_UPSTREAM
	int (*filter_insert)(struct efx_auxdev_client *handle,
			     const struct efx_filter_spec *spec,
			     bool replace_equal);
	int (*filter_remove)(struct efx_auxdev_client *handle,
			     int filter_id);
	int (*get_param)(struct efx_auxdev_client *handle,
			 enum efx_auxiliary_param p,
			 union efx_auxiliary_param_value *arg);
	int (*set_param)(struct efx_auxdev_client *handle,
			 enum efx_auxiliary_param p,
			 union efx_auxiliary_param_value *arg);
	struct efx_auxdev_dl_vi_resources *
		(*dl_publish)(struct efx_auxdev_client *handle);
	void (*dl_unpublish)(struct efx_auxdev_client *handle);
#endif
};

/**
 * struct efx_auxdev - Auxiliary device interface.
 *
 * @auxdev: The parent auxiliary bus device.
 * @ops: Device API.
 */
struct efx_auxdev {
	struct auxiliary_device auxdev;
	const struct efx_auxdev_ops *ops;
};

static inline struct efx_auxdev *to_efx_auxdev(struct auxiliary_device *adev)
{
	return container_of(adev, struct efx_auxdev, auxdev);
}
#endif /* _EFX_AUXBUS_H */
