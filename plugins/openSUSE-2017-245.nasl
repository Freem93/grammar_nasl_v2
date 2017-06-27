#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-245.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97274);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/21 14:37:43 $");

  script_cve_id("CVE-2015-8709", "CVE-2016-7117", "CVE-2016-8645", "CVE-2016-9793", "CVE-2016-9806", "CVE-2016-9919", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-5551", "CVE-2017-5576", "CVE-2017-5577");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-245)");
  script_summary(english:"Check for the openSUSE-2017-245 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 42.2 kernel was updated to 4.4.42 stable release.

The following security bugs were fixed :

  - CVE-2016-7117: Use-after-free vulnerability in the
    __sys_recvmmsg function in net/socket.c in the Linux
    kernel allowed remote attackers to execute arbitrary
    code via vectors involving a recvmmsg system call that
    is mishandled during error processing (bnc#1003077
    1003253).

  - CVE-2017-5576, CVE-2017-5577: A buffer overflow in the
    VC4_SUBMIT_CL IOCTL in the VideoCore DRM driver for
    Raspberry Pi was fixed. (bsc#1021294)

  - CVE-2017-5551: tmpfs: Fixed a bug that could have
    allowed users to set setgid bits on files they don't
    down. (bsc#1021258).

  - CVE-2017-2583: A Linux kernel built with the
    Kernel-based Virtual Machine (CONFIG_KVM) support was
    vulnerable to an incorrect segment selector(SS) value
    error. A user/process inside guest could have used this
    flaw to crash the guest resulting in DoS or potentially
    escalate their privileges inside guest. (bsc#1020602).

  - CVE-2017-2584: arch/x86/kvm/emulate.c in the Linux
    kernel allowed local users to obtain sensitive
    information from kernel memory or cause a denial of
    service (use-after-free) via a crafted application that
    leverages instruction emulation for fxrstor, fxsave,
    sgdt, and sidt (bnc#1019851).

  - CVE-2015-8709: ** DISPUTED ** kernel/ptrace.c in the
    Linux kernel mishandled uid and gid mappings, which
    allowed local users to gain privileges by establishing a
    user namespace, waiting for a root process to enter that
    namespace with an unsafe uid or gid, and then using the
    ptrace system call. NOTE: the vendor states 'there is no
    kernel bug here (bnc#959709 bsc#960561).

  - CVE-2016-9806: Race condition in the netlink_dump
    function in net/netlink/af_netlink.c in the Linux kernel
    allowed local users to cause a denial of service (double
    free) or possibly have unspecified other impact via a
    crafted application that made sendmsg system calls,
    leading to a free operation associated with a new dump
    that started earlier than anticipated (bnc#1013540
    1017589).

  - CVE-2016-8645: The TCP stack in the Linux kernel
    mishandled skb truncation, which allowed local users to
    cause a denial of service (system crash) via a crafted
    application that made sendto system calls, related to
    net/ipv4/tcp_ipv4.c and net/ipv6/tcp_ipv6.c
    (bnc#1009969).

  - CVE-2016-9793: The sock_setsockopt function in
    net/core/sock.c in the Linux kernel mishandled negative
    values of sk_sndbuf and sk_rcvbuf, which allowed local
    users to cause a denial of service (memory corruption
    and system crash) or possibly have unspecified other
    impact by leveraging the CAP_NET_ADMIN capability for a
    crafted setsockopt system call with the (1)
    SO_SNDBUFFORCE or (2) SO_RCVBUFFORCE option (bnc#1013531
    bsc#1013542).

  - CVE-2016-9919: The icmp6_send function in
    net/ipv6/icmp.c in the Linux kernel omits a certain
    check of the dst data structure, which allowed remote
    attackers to cause a denial of service (panic) via a
    fragmented IPv6 packet (bnc#1014701).

The following non-security bugs were fixed :

  - 8250/fintek: rename IRQ_MODE macro (boo#1009546).

  - acpi, nfit: fix bus vs dimm confusion in xlat_status
    (bsc#1023175).

  - acpi, nfit, libnvdimm: fix / harden ars_status output
    length handling (bsc#1023175).

  - acpi, nfit: validate ars_status output buffer size
    (bsc#1023175).

  - arm64/numa: fix incorrect log for memory-less node
    (bsc#1019631).

  - ASoC: cht_bsw_rt5645: Fix leftover kmalloc
    (bsc#1010690).

  - ASoC: Intel: bytcr_rt5640: fallback mechanism if MCLK is
    not enabled (bsc#1010690).

  - ASoC: rt5670: add HS ground control (bsc#1016250).

  - avoid including 'mountproto=' with no protocol in
    /proc/mounts (bsc#1019260).

  - bcache: Make gc wakeup sane, remove set_task_state()
    (bsc#1021260).

  - bcache: partition support: add 16 minors per bcacheN
    device (bsc#1019784).

  - blacklist.conf: add 1b8d2afde54f libnvdimm, pfn: fix
    ARCH=alpha allmodconfig build failure (bsc#1023175).

  - blacklist.conf: Add i915 stable commits that can be
    ignored (bsc#1015367)

  - blk: Do not collide with QUEUE_FLAG_WC from upstream
    (bsc#1022547)

  - blk-mq: Allow timeouts to run while queue is freezing
    (bsc#1020817).

  - blk-mq: Always schedule hctx->next_cpu (bsc#1020817).

  - blk-mq: Avoid memory reclaim when remapping queues
    (bsc#1020817).

  - blk-mq: do not overwrite rq->mq_ctx (bsc#1020817).

  - blk-mq: Fix failed allocation path when mapping queues
    (bsc#1020817).

  - blk-mq: improve warning for running a queue on the wrong
    CPU (bsc#1020817).

  - block: Change extern inline to static inline
    (bsc#1023175).

  - Bluetooth: btmrvl: fix hung task warning dump
    (bsc#1018813).

  - bnx2x: Correct ringparam estimate when DOWN
    (bsc#1020214).

  - brcmfmac: Change error print on wlan0 existence
    (bsc#1000092).

  - btrfs: add support for RENAME_EXCHANGE and
    RENAME_WHITEOUT (bsc#1020975).

  - btrfs: bugfix: handle
    FS_IOC32_{GETFLAGS,SETFLAGS,GETVERSION} in btrfs_ioctl
    (bsc#1018100).

  - btrfs: fix inode leak on failure to setup whiteout inode
    in rename (bsc#1020975).

  - btrfs: fix lockdep warning about log_mutex
    (bsc#1021455).

  - btrfs: fix lockdep warning on deadlock against an
    inode's log mutex (bsc#1021455).

  - btrfs: fix number of transaction units for renames with
    whiteout (bsc#1020975).

  - btrfs: incremental send, fix invalid paths for rename
    operations (bsc#1018316).

  - btrfs: incremental send, fix premature rmdir operations
    (bsc#1018316).

  - btrfs: increment ctx->pos for every emitted or skipped
    dirent in readdir (bsc#981709).

  - btrfs: pin log earlier when renaming (bsc#1020975).

  - btrfs: pin logs earlier when doing a rename exchange
    operation (bsc#1020975).

  - btrfs: remove old tree_root dirent processing in
    btrfs_real_readdir() (bsc#981709).

  - btrfs: send, add missing error check for calls to
    path_loop() (bsc#1018316).

  - btrfs: send, avoid incorrect leaf accesses when sending
    utimes operations (bsc#1018316).

  - btrfs: send, fix failure to move directories with the
    same name around (bsc#1018316).

  - btrfs: send, fix invalid leaf accesses due to incorrect
    utimes operations (bsc#1018316).

  - btrfs: send, fix warning due to late freeing of
    orphan_dir_info structures (bsc#1018316).

  - btrfs: test_check_exists: Fix infinite loop when
    searching for free space entries (bsc#987192).

  - btrfs: unpin log if rename operation fails
    (bsc#1020975).

  - btrfs: unpin logs if rename exchange operation fails
    (bsc#1020975).

  - [BZ 149851] kernel: Fix invalid domain response handling
    (bnc#1009718, LTC#149851).

  - ceph: fix bad endianness handling in
    parse_reply_info_extra (bsc#1020488).

  - clk: xgene: Add PMD clock (bsc#1019351).

  - clk: xgene: Do not call __pa on ioremaped address
    (bsc#1019351).

  - clk: xgene: Remove CLK_IS_ROOT (bsc#1019351).

  - config: enable Ceph kernel client modules for ppc64le
    (fate#321098)

  - config: enable Ceph kernel client modules for s390x
    (fate#321098)

  - config: enable CONFIG_OCFS2_DEBUG_MASKLOG for ocfs2
    (bsc#1015038)

  - crypto: drbg - do not call drbg_instantiate in healt
    test (bsc#1018913).

  - crypto: drbg - remove FIPS 140-2 continuous test
    (bsc#1018913).

  - crypto: FIPS - allow tests to be disabled in FIPS mode
    (bsc#1018913).

  - crypto: qat - fix bar discovery for c62x (bsc#1021251).

  - crypto: qat - zero esram only for DH85x devices
    (1021248).

  - crypto: rsa - allow keys >= 2048 bits in FIPS mode
    (bsc#1018913).

  - crypto: xts - consolidate sanity check for keys
    (bsc#1018913).

  - crypto: xts - fix compile errors (bsc#1018913).

  - cxl: fix potential NULL dereference in free_adapter()
    (bsc#1016517).

  - dax: fix deadlock with DAX 4k holes (bsc#1012829).

  - dax: fix device-dax region base (bsc#1023175).

  - device-dax: check devm_nsio_enable() return value
    (bsc#1023175).

  - device-dax: fail all private mapping attempts
    (bsc#1023175).

  - device-dax: fix percpu_ref_exit ordering (bsc#1023175).

  - driver core: fix race between creating/querying glue dir
    and its cleanup (bnc#1008742).

  - drivers:hv: balloon: account for gaps in hot add regions
    (fate#320485).

  - drivers:hv: balloon: Add logging for dynamic memory
    operations (fate#320485).

  - drivers:hv: balloon: Disable hot add when
    CONFIG_MEMORY_HOTPLUG is not set (fate#320485).

  - drivers:hv: balloon: Fix info request to show max page
    count (fate#320485).

  - drivers:hv: balloon: keep track of where ha_region
    starts (fate#320485).

  - drivers:hv: balloon: replace ha_region_mutex with
    spinlock (fate#320485).

  - drivers:hv: balloon: Use available memory value in
    pressure report (fate#320485).

  - drivers:hv: cleanup vmbus_open() for wrap around
    mappings (fate#320485).

  - drivers:hv: do not leak memory in
    vmbus_establish_gpadl() (fate#320485).

  - drivers:hv: get rid of id in struct vmbus_channel
    (fate#320485).

  - drivers:hv: get rid of redundant messagecount in
    create_gpadl_header() (fate#320485).

  - drivers:hv: get rid of timeout in vmbus_open()
    (fate#320485).

  - drivers:hv: Introduce a policy for controlling channel
    affinity (fate#320485).

  - drivers:hv: make VMBus bus ids persistent (fate#320485).

  - drivers:hv: ring_buffer: count on wrap around mappings
    in get_next_pkt_raw() (v2) (fate#320485).

  - drivers:hv: ring_buffer: use wrap around mappings in
    hv_copy{from, to}_ringbuffer() (fate#320485).

  - drivers:hv: ring_buffer: wrap around mappings for ring
    buffers (fate#320485).

  - drivers:hv: utils: Check VSS daemon is listening before
    a hot backup (fate#320485).

  - drivers:hv: utils: Continue to poll VSS channel after
    handling requests (fate#320485).

  - drivers:hv: utils: fix a race on userspace daemons
    registration (bnc#1014392).

  - drivers:hv: utils: Fix the mapping between host version
    and protocol to use (fate#320485).

  - drivers:hv: utils: reduce HV_UTIL_NEGO_TIMEOUT timeout
    (fate#320485).

  - drivers:hv: vmbus: Base host signaling strictly on the
    ring state (fate#320485).

  - drivers:hv: vmbus: Enable explicit signaling policy for
    NIC channels (fate#320485).

  - drivers:hv: vmbus: finally fix
    hv_need_to_signal_on_read() (fate#320485, bug#1018385).

  - drivers:hv: vmbus: fix the race when querying & updating
    the percpu list (fate#320485).

  - drivers:hv: vmbus: Implement a mechanism to tag the
    channel for low latency (fate#320485).

  - drivers: hv: vmbus: Make mmio resource local
    (fate#320485).

  - drivers:hv: vmbus: On the read path cleanup the logic to
    interrupt the host (fate#320485).

  - drivers:hv: vmbus: On write cleanup the logic to
    interrupt the host (fate#320485).

  - drivers:hv: vmbus: Reduce the delay between retries in
    vmbus_post_msg() (fate#320485).

  - drivers:hv: vmbus: suppress some 'hv_vmbus: Unknown
    GUID' warnings (fate#320485).

  - drivers:hv: vss: Improve log messages (fate#320485).

  - drivers:hv: vss: Operation timeouts should match host
    expectation (fate#320485).

  - drivers: net: phy: mdio-xgene: Add hardware dependency
    (bsc#1019351).

  - drivers: net: phy: xgene: Fix 'remove' function
    (bsc#1019351).

  - drivers: net: xgene: Add change_mtu function
    (bsc#1019351).

  - drivers: net: xgene: Add flow control configuration
    (bsc#1019351).

  - drivers: net: xgene: Add flow control initialization
    (bsc#1019351).

  - drivers: net: xgene: Add helper function (bsc#1019351).

  - drivers: net: xgene: Add support for Jumbo frame
    (bsc#1019351).

  - drivers: net: xgene: Configure classifier with pagepool
    (bsc#1019351).

  - drivers: net: xgene: fix build after change_mtu function
    change (bsc#1019351).

  - drivers: net: xgene: fix: Coalescing values for v2
    hardware (bsc#1019351).

  - drivers: net: xgene: fix: Disable coalescing on v1
    hardware (bsc#1019351).

  - drivers: net: xgene: Fix MSS programming (bsc#1019351).

  - drivers: net: xgene: fix: RSS for non-TCP/UDP
    (bsc#1019351).

  - drivers: net: xgene: fix: Use GPIO to get link status
    (bsc#1019351).

  - drivers: net: xgene: uninitialized variable in
    xgene_enet_free_pagepool() (bsc#1019351).

  - drm: Fix broken VT switch with video=1366x768 option
    (bsc#1018358).

  - drm/i915: add helpers for platform specific revision id
    range checks (bsc#1015367).

  - drm/i915: Apply broader WaRsDisableCoarsePowerGating for
    guc also (bsc#1015367).

  - drm/i915/bxt: add revision id for A1 stepping and use it
    (bsc#1015367).

  - drm/i915: Call intel_dp_mst_resume() before resuming
    displays (bsc#1015359).

  - drm/i915: Cleaning up DDI translation tables
    (bsc#1014392).

  - drm/i915: Clean up L3 SQC register field definitions
    (bsc#1014392).

  - drm/i915: Do not init hpd polling for vlv and chv from
    runtime_suspend() (bsc#1014120).

  - drm-i915-dp-Restore-PPS-HW-state-from-the-encoder-re

  - drm/i915/dp: Restore PPS HW state from the encoder
    resume hook (bsc#1019061).

  - drm/i915/dsi: fix CHV dsi encoder hardware state readout
    on port C (bsc#1015367).

  - drm/i915: Exit cherryview_irq_handler() after one pass
    (bsc#1015367).

  - drm/i915: Fix iboost setting for SKL Y/U DP DDI buffer
    translation entry 2 (bsc#1014392).

  - drm/i915: Fix system resume if PCI device remained
    enabled (bsc#1015367).

  - drm/i915: Fix watermarks for VLV/CHV (bsc#1011176).

  - drm/i915: Force ringbuffers to not be at offset 0
    (bsc#1015367).

  - drm/i915: Force VDD off on the new power seqeuencer
    before starting to use it (bsc#1009674).

  - drm/i915/gen9: Add WaInPlaceDecompressionHang
    (bsc#1014392).

  - drm/i915/gen9: Fix PCODE polling during CDCLK change
    notification (bsc#1015367).

  - drm/i915: Mark CPU cache as dirty when used for
    rendering (bsc#1015367).

  - drm/i915: Mark i915_hpd_poll_init_work as static
    (bsc#1014120).

  - drm-i915-Prevent-PPS-stealing-from-a-normal-DP-port

  - drm/i915: Prevent PPS stealing from a normal DP port on
    VLV/CHV (bsc#1019061).

  - drm/i915: remove parens around revision ids
    (bsc#1015367).

  - drm/i915/skl: Add WaDisableGafsUnitClkGating
    (bsc#1014392).

  - drm/i915/skl: Fix rc6 based gpu/system hang
    (bsc#1015367).

  - drm/i915/skl: Fix spurious gpu hang with gt3/gt4 revs
    (bsc#1015367).

  - drm/i915/skl: Update DDI translation tables for SKL
    (bsc#1014392).

  - drm/i915/skl: Update watermarks before the crtc is
    disabled (bsc#1015367).

  - drm/i915: Update Skylake DDI translation table for DP
    (bsc#1014392).

  - drm/i915: Update Skylake DDI translation table for HDMI
    (bsc#1014392).

  - drm/i915/userptr: Hold mmref whilst calling
    get-user-pages (bsc#1015367).

  - drm/i915/vlv: Prevent enabling hpd polling in late
    suspend (bsc#1014120).

  - drm/i915: Workaround for DP DPMS D3 on Dell monitor
    (bsc#1019061).

  - drm: Use u64 for intermediate dotclock calculations
    (bnc#1006472).

  - drm/vc4: Fix an integer overflow in temporary allocation
    layout (bsc#1021294).

  - drm/vc4: Return -EINVAL on the overflow checks failing
    (bsc#1021294).

  - drm: virtio-gpu: get the fb from the plane state for
    atomic updates (bsc#1023101).

  - EDAC, xgene: Fix spelling mistake in error messages
    (bsc#1019351).

  - efi/libstub: Move Graphics Output Protocol handling to
    generic code (bnc#974215).

  - fbcon: Fix vc attr at deinit (bsc#1000619).

  - Fix kABI breakage by i2c-designware baytrail fix
    (bsc#1011913).

  - Fix kABI breakage by linux/acpi.h inclusion in
    i8042-x86ia46io.h (bsc#1011660).

  - gpio: xgene: make explicitly non-modular (bsc#1019351).

  - gro_cells: mark napi struct as not busy poll candidates
    (bsc#966191 FATE#320230 bsc#966186 FATE#320228).

  - hv: acquire vmbus_connection.channel_mutex in
    vmbus_free_channels() (fate#320485).

  - hv: change clockevents unbind tactics (fate#320485).

  - hv: do not reset hv_context.tsc_page on crash
    (fate#320485, bnc#1007729).

  - hv_netvsc: add ethtool statistics for tx packet issues
    (fate#320485).

  - hv_netvsc: Add handler for physical link speed change
    (fate#320485).

  - hv_netvsc: Add query for initial physical link speed
    (fate#320485).

  - hv_netvsc: count multicast packets received
    (fate#320485).

  - hv_netvsc: dev hold/put reference to VF (fate#320485).

  - hv_netvsc: fix a race between netvsc_send() and
    netvsc_init_buf() (fate#320485).

  - hv_netvsc: fix comments (fate#320485).

  - hv_netvsc: fix rtnl locking in callback (fate#320485).

  - hv_netvsc: Implement batching of receive completions
    (fate#320485).

  - hv_netvsc: improve VF device matching (fate#320485).

  - hv_netvsc: init completion during alloc (fate#320485).

  - hv_netvsc: make device_remove void (fate#320485).

  - hv_netvsc: make inline functions static (fate#320485).

  - hv_netvsc: make netvsc_destroy_buf void (fate#320485).

  - hv_netvsc: make RSS hash key static (fate#320485).

  - hv_netvsc: make variable local (fate#320485).

  - hv_netvsc: rearrange start_xmit (fate#320485).

  - hv_netvsc: refactor completion function (fate#320485).

  - hv_netvsc: remove excessive logging on MTU change
    (fate#320485).

  - hv_netvsc: remove VF in flight counters (fate#320485).

  - hv_netvsc: report vmbus name in ethtool (fate#320485).

  - hv_netvsc: simplify callback event code (fate#320485).

  - hv_netvsc: style cleanups (fate#320485).

  - hv_netvsc: use ARRAY_SIZE() for NDIS versions
    (fate#320485).

  - hv_netvsc: use consume_skb (fate#320485).

  - hv_netvsc: use kcalloc (fate#320485).

  - hv_netvsc: use RCU to protect vf_netdev (fate#320485).

  - hyperv: Fix spelling of HV_UNKOWN (fate#320485).

  - i2c: designware-baytrail: Disallow the CPU to enter C6
    or C7 while holding the punit semaphore (bsc#1011913).

  - i2c: designware: fix wrong Tx/Rx FIFO for ACPI
    (bsc#1019351).

  - i2c: designware: Implement support for SMBus block read
    and write (bsc#1019351).

  - i2c: xgene: Fix missing code of DTB support
    (bsc#1019351).

  - i40e: Be much more verbose about what we can and cannot
    offload (bsc#985561).

  - i915: Delete previous two fixes for i915 (bsc#1019061).
    These upstream fixes brought some regressions, so better
    to revert for now.

  - i915: Disable
    patches.drivers/drm-i915-Exit-cherryview_irq_handler-aft
    er-one-pass The patch seems leading to the instability
    on Wyse box (bsc#1015367).

  - IB/core: Fix possible memory leak in
    cma_resolve_iboe_route() (bsc#966191 FATE#320230
    bsc#966186 FATE#320228).

  - IB/mlx5: Fix iteration overrun in GSI qps (bsc#966170
    FATE#320225 bsc#966172 FATE#320226).

  - IB/mlx5: Fix steering resource leak (bsc#966170
    FATE#320225 bsc#966172 FATE#320226).

  - IB/mlx5: Set source mac address in FTE (bsc#966170
    FATE#320225 bsc#966172 FATE#320226).

  - ibmveth: calculate gso_segs for large packets
    (bsc#1019148).

  - ibmveth: check return of skb_linearize in
    ibmveth_start_xmit (bsc#1019148).

  - ibmveth: consolidate kmalloc of array, memset 0 to
    kcalloc (bsc#1019148).

  - ibmveth: set correct gso_size and gso_type
    (bsc#1019148).

  - ibmvnic: convert to use simple_open() (bsc#1015416).

  - ibmvnic: Driver Version 1.0.1 (bsc#1015416).

  - ibmvnic: drop duplicate header seq_file.h (bsc#1015416).

  - ibmvnic: fix error return code in ibmvnic_probe()
    (bsc#1015416).

  - ibmvnic: Fix GFP_KERNEL allocation in interrupt context
    (bsc#1015416).

  - ibmvnic: Fix missing brackets in init_sub_crq_irqs
    (bsc#1015416).

  - ibmvnic: Fix releasing of sub-CRQ IRQs in interrupt
    context (bsc#1015416).

  - ibmvnic: Fix size of debugfs name buffer (bsc#1015416).

  - ibmvnic: Handle backing device failover and
    reinitialization (bsc#1015416).

  - ibmvnic: Start completion queue negotiation at
    server-provided optimum values (bsc#1015416).

  - ibmvnic: Unmap ibmvnic_statistics structure
    (bsc#1015416).

  - ibmvnic: Update MTU after device initialization
    (bsc#1015416).

  - igb: add i211 to i210 PHY workaround (bsc#1009911).

  - igb: Workaround for igb i210 firmware issue
    (bsc#1009911).

  - Input: i8042 - Trust firmware a bit more when probing on
    X86 (bsc#1011660).

  - intel_idle: Add KBL support (bsc#1016884).

  - ipc: msg, make msgrcv work with LONG_MIN (bnc#1005918).

  - ipc/sem.c: add cond_resched in exit_sme (bsc#979378).

  - ixgbe: Do not clear RAR entry when clearing VMDq for SAN
    MAC (bsc#969474 FATE#319812 bsc#969475 FATE#319814).

  - ixgbe: Force VLNCTRL.VFE to be set in all VMDq paths
    (bsc#969474 FATE#319812 bsc#969475 FATE#319814).

  - KABI fix (bsc#1014410).

  - kABI: protect struct mm_struct (kabi).

  - kABI: protect struct musb_platform_ops (kabi).

  - kABI: protect struct task_struct (kabi).

  - kABI: protect struct user_fpsimd_state (kabi).

  - kABI: protect struct wake_irq (kabi).

  - kABI: protect struct xhci_hcd (kabi).

  - kABI: protect user_namespace include in fs/exec (kabi).

  - kABI: protect user_namespace include in kernel/ptrace
    (kabi).

  - kabi/severities: Ignore changes in drivers/hv

  - kgraft/iscsi-target: Do not block kGraft in iscsi_np
    kthread (bsc#1010612, fate#313296).

  - kgraft/xen: Do not block kGraft in xenbus kthread
    (bsc#1017410, fate#313296).

  - libnvdimm, pfn: fix align attribute (bsc#1023175).

  - locking/pv-qspinlock: Use cmpxchg_release() in
    __pv_queued_spin_unlock() (bsc#969756).

  - locking/rtmutex: Prevent dequeue vs. unlock race
    (bsc#1015212).

  - locking/rtmutex: Use READ_ONCE() in rt_mutex_owner()
    (bsc#1015212).

  - mailbox: xgene-slimpro: Fix wrong test for devm_kzalloc
    (bsc#1019351).

  - md-cluster: convert the completion to wait queue
    (fate#316335).

  - md-cluster: protect md_find_rdev_nr_rcu with rcu lock
    (fate#316335).

  - md: fix refcount problem on mddev when stopping array
    (bsc#1022304).

  - md linear: fix a race between linear_add() and
    linear_congested() (bsc#1018446).

  - [media] uvcvideo: uvc_scan_fallback() for webcams with
    broken chain (bsc#1021474).

  - misc/genwqe: ensure zero initialization (fate#321595).

  - mmc: sdhci-of-arasan: Remove no-hispd and no-cmd23
    quirks for sdhci-arasan4.9a (bsc#1019351).

  - mm: do not loop on GFP_REPEAT high order requests if
    there is no reclaim progress (bnc#1013000).

  - mm, memcg: do not retry precharge charges (bnc#1022559).

  - mm, page_alloc: fix check for NULL preferred_zone
    (bnc#971975 VM performance -- page allocator).

  - mm, page_alloc: fix fast-path race with cpuset update or
    removal (bnc#971975 VM performance -- page allocator).

  - mm, page_alloc: fix premature OOM when racing with
    cpuset mems update (bnc#971975 VM performance -- page
    allocator).

  - mm, page_alloc: keep pcp count and list contents in sync
    if struct page is corrupted (bnc#971975 VM performance
    -- page allocator).

  - mm, page_alloc: move cpuset seqcount checking to
    slowpath (bnc#971975 VM performance -- page allocator).

  - mwifiex: add missing check for PCIe8997 chipset
    (bsc#1018813).

  - mwifiex: fix IBSS data path issue (bsc#1018813).

  - mwifiex: fix PCIe register information for 8997 chipset
    (bsc#1018813).

  - net/af_iucv: do not use paged skbs for TX on
    HiperSockets (bnc#1020945, LTC#150566).

  - net: ethernet: apm: xgene: use phydev from struct
    net_device (bsc#1019351).

  - net/hyperv: avoid uninitialized variable (fate#320485).

  - net: icmp6_send should use dst dev to determine L3
    domain (bsc#1014701).

  - net: ipv6: tcp reset, icmp need to consider L3 domain
    (bsc#1014701).

  - net/mlx4_en: Fix panic on xmit while port is down
    (bsc#966191 FATE#320230).

  - net/mlx5e: Use correct flow dissector key on flower
    offloading (bsc#966170 FATE#320225 bsc#966172
    FATE#320226).

  - net/mlx5: Fix autogroups groups num not decreasing
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - net/mlx5: Keep autogroups list ordered (bsc#966170
    FATE#320225 bsc#966172 FATE#320226).

  - net: remove useless memset's in drivers get_stats64
    (bsc#1019351).

  - net_sched: fix a typo in tc_for_each_action()
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - netvsc: add rcu_read locking to netvsc callback
    (fate#320485).

  - netvsc: fix checksum on UDP IPV6 (fate#320485).

  - netvsc: reduce maximum GSO size (fate#320485).

  - netvsc: Remove mistaken udp.h inclusion (fate#320485).

  - net: xgene: avoid bogus maybe-uninitialized warning
    (bsc#1019351).

  - net: xgene: fix backward compatibility fix
    (bsc#1019351).

  - net/xgene: fix error handling during reset
    (bsc#1019351).

  - net: xgene: move xgene_cle_ptree_ewdn data off stack
    (bsc#1019351).

  - nfit: fail DSMs that return non-zero status by default
    (bsc#1023175).

  - NFSv4: Cap the transport reconnection timer at 1/2 lease
    period (bsc#1014410).

  - NFSv4: Cleanup the setting of the nfs4 lease period
    (bsc#1014410).

  - nvdimm: kabi protect nd_cmd_out_size() (bsc#1023175).

  - nvme: apply DELAY_BEFORE_CHK_RDY quirk at probe time too
    (bsc#1020685).

  - ocfs2: fix deadlock on mmapped page in
    ocfs2_write_begin_nolock() (bnc#921494).

  - pci: Add devm_request_pci_bus_resources() (bsc#1019351).

  - PCI/AER: include header file (bsc#964944,FATE#319965).

  - pci: generic: Fix pci_remap_iospace() failure path
    (bsc#1019630).

  - pci: hv: Allocate physically contiguous hypercall params
    buffer (fate#320485).

  - pci: hv: Delete the device earlier from hbus->children
    for hot-remove (fate#320485).

  - pci: hv: Fix hv_pci_remove() for hot-remove
    (fate#320485).

  - pci: hv: Handle hv_pci_generic_compl() error case
    (fate#320485).

  - pci: hv: Handle vmbus_sendpacket() failure in
    hv_compose_msi_msg() (fate#320485).

  - pci: hv: Make unnecessarily global IRQ masking functions
    static (fate#320485).

  - pci: hv: Remove the unused 'wrk' in struct
    hv_pcibus_device (fate#320485).

  - pci: hv: Use list_move_tail() instead of list_del() +
    list_add_tail() (fate#320485).

  - pci: hv: Use pci_function_description in struct
    definitions (fate#320485).

  - pci: hv: Use the correct buffer size in
    new_pcichild_device() (fate#320485).

  - pci: hv: Use zero-length array in struct pci_packet
    (fate#320485).

  - pci: xgene: Add local struct device pointers
    (bsc#1019351).

  - pci: xgene: Add register accessors (bsc#1019351).

  - pci: xgene: Free bridge resource list on failure
    (bsc#1019351).

  - pci: xgene: Make explicitly non-modular (bsc#1019351).

  - pci: xgene: Pass struct xgene_pcie_port to setup
    functions (bsc#1019351).

  - pci: xgene: Remove unused platform data (bsc#1019351).

  - pci: xgene: Request host bridge window resources
    (bsc#1019351).

  - perf: xgene: Remove bogus IS_ERR() check (bsc#1019351).

  - phy: xgene: rename 'enum phy_mode' to 'enum
    xgene_phy_mode' (bsc#1019351).

  - powerpc/fadump: Fix the race in crash_fadump()
    (bsc#1022971).

  - power: reset: xgene-reboot: Unmap region obtained by
    of_iomap (bsc#1019351).

  - qeth: check not more than 16 SBALEs on the completion
    queue (bnc#1009718, LTC#148203).

  - raid1: ignore discard error (bsc#1017164).

  - reiserfs: fix race in prealloc discard (bsc#987576).

  - rpm/kernel-binary.spec.in: Export a make-stderr.log file
    (bsc#1012422)

  - rpm/kernel-binary.spec.in: Fix installation of
    /etc/uefi/certs (bsc#1019594)

  - rtc: cmos: avoid unused function warning (bsc#1022429).

  - rtc: cmos: Clear ACPI-driven alarms upon resume
    (bsc#1022429).

  - rtc: cmos: Do not enable interrupts in the middle of the
    interrupt handler (bsc#1022429).

  - rtc: cmos: Restore alarm after resume (bsc#1022429).

  - s390/cpuinfo: show maximum thread id (bnc#1009718,
    LTC#148580).

  - s390/sysinfo: show partition extended name and UUID if
    available (bnc#1009718, LTC#150160).

  - s390/time: LPAR offset handling (bnc#1009718,
    LTC#146920).

  - s390/time: move PTFF definitions (bnc#1009718,
    LTC#146920).

  - sched: Allow hotplug notifiers to be setup early
    (bnc#1022476).

  - sched/core: Fix incorrect utilization accounting when
    switching to fair class (bnc#1022476).

  - sched/core: Fix set_user_nice() (bnc#1022476).

  - sched/core, x86/topology: Fix NUMA in package topology
    bug (bnc#1022476).

  - sched/cputime: Add steal time support to full dynticks
    CPU time accounting (bnc#1022476).

  - sched/cputime: Fix prev steal time accouting during CPU
    hotplug (bnc#1022476).

  - sched/deadline: Always calculate end of period on
    sched_yield() (bnc#1022476).

  - sched/deadline: Fix a bug in dl_overflow()
    (bnc#1022476).

  - sched/deadline: Fix lock pinning warning during CPU
    hotplug (bnc#1022476).

  - sched/deadline: Fix wrap-around in DL heap
    (bnc#1022476).

  - sched/fair: Avoid using decay_load_missed() with a
    negative value (bnc#1022476).

  - sched/fair: Fix fixed point arithmetic width for shares
    and effective load (bnc#1022476).

  - sched/fair: Fix load_above_capacity fixed point
    arithmetic width (bnc#1022476).

  - sched/fair: Fix min_vruntime tracking (bnc#1022476).

  - sched/fair: Fix the wrong throttled clock time for
    cfs_rq_clock_task() (bnc#1022476).

  - sched/fair: Improve PELT stuff some more (bnc#1022476).

  - sched: Make wake_up_nohz_cpu() handle CPUs going offline
    (bnc#1022476).

  - sched/rt: Fix PI handling vs. sched_setscheduler()
    (bnc#1022476).

  - sched/rt: Kick RT bandwidth timer immediately on start
    up (bnc#1022476).

  - sched/rt, sched/dl: Do not push if task's scheduling
    class was changed (bnc#1022476).

  - scsi: Add 'AIX VDASD' to blacklist (bsc#1006469).

  - scsi: bfa: Increase requested firmware version to
    3.2.5.1 (bsc#1013273).

  - scsi_dh_alua: uninitialized variable in alua_rtpg()
    (bsc#1012910).

  - scsi: Modify HITACHI OPEN-V blacklist entry
    (bsc#1006469).

  - scsi: storvsc: Payload buffer incorrectly sized for 32
    bit kernels (fate#320485).

  - sd: always scan VPD pages if thin provisioning is
    enabled (bsc#1013792).

  - serial: 8250_fintek: fix the mismatched IRQ mode
    (boo#1009546).

  - serial: 8250: Integrate Fintek into 8250_base
    (boo#1016979). Update config files to change
    CONFIG_SERIAL_8250_FINTEK to boolean accordingly, too.
    Also, the corresponding entry got removed from
    supported.conf.

  - ses: Fix SAS device detection in enclosure
    (bsc#1016403).

  - sunrpc: Fix reconnection timeouts (bsc#1014410).

  - sunrpc: fix refcounting problems with auth_gss messages
    (boo#1011250).

  - sunrpc: Limit the reconnect backoff timer to the max RPC
    message timeout (bsc#1014410).

  - supported.conf: delete xilinx/ll_temac (bsc#1011602)

  - supported.conf: Support Marvell WiFi/BT SDIO and
    pinctrl-cherrytrail (bsc#1018813)

  - target: add XCOPY target/segment desc sense codes
    (bsc#991273).

  - target: bounds check XCOPY segment descriptor list
    (bsc#991273).

  - target: bounds check XCOPY total descriptor list length
    (bsc#991273).

  - target: check for XCOPY parameter truncation
    (bsc#991273).

  - target: check XCOPY segment descriptor CSCD IDs
    (bsc#1017170).

  - target: return UNSUPPORTED TARGET/SEGMENT DESC TYPE CODE
    sense (bsc#991273).

  - target: simplify XCOPY wwn->se_dev lookup helper
    (bsc#991273).

  - target: support XCOPY requests without parameters
    (bsc#991273).

  - target: use XCOPY segment descriptor CSCD IDs
    (bsc#1017170).

  - target: use XCOPY TOO MANY TARGET DESCRIPTORS sense
    (bsc#991273).

  - tools: hv: Enable network manager for bonding scripts on
    RHEL (fate#320485).

  - tools: hv: fix a compile warning in snprintf
    (fate#320485).

  - Tools: hv: kvp: configurable external scripts path
    (fate#320485).

  - Tools: hv: kvp: ensure kvp device fd is closed on exec
    (fate#320485).

  - tools: hv: remove unnecessary header files and netlink
    related code (fate#320485).

  - tools: hv: remove unnecessary link flag (fate#320485).

  - tty: n_hdlc, fix lockdep false positive (bnc#1015840).

  - Update metadata for serial fixes (bsc#1013001)

  - vmbus: make sysfs names consistent with PCI
    (fate#320485).

  - x86/hpet: Reduce HPET counter read contention
    (bsc#1014710).

  - x86/hyperv: Handle unknown NMIs on one CPU when
    unknown_nmi_panic (fate#320485).

  - x86/MCE: Dump MCE to dmesg if no consumers
    (bsc#1013994)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=921494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991273"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-debuginfo-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debuginfo-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debugsource-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-debuginfo-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-debuginfo-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debuginfo-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debugsource-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-devel-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-devel-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-html-4.4.46-11.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-pdf-4.4.46-11.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-macros-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-debugsource-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-qa-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-vanilla-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-syms-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-debuginfo-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debuginfo-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debugsource-4.4.46-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-devel-4.4.46-11.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-docs-html / kernel-docs-pdf / kernel-devel / kernel-macros / etc");
}
