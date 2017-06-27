#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0575-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(97466);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/01 14:52:06 $");

  script_cve_id("CVE-2015-8709", "CVE-2016-7117", "CVE-2016-9806", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-5551", "CVE-2017-5576", "CVE-2017-5577", "CVE-2017-5897", "CVE-2017-5970", "CVE-2017-5986");
  script_osvdb_id(132475, 145048, 148137, 150064, 150690, 150791, 150792, 150899, 151568, 151927, 152094);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2017:0575-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 SP2 kernel was updated to 4.4.49 to
receive various security and bugfixes. The following security bugs
were fixed :

  - CVE-2016-7117: Use-after-free vulnerability in the
    __sys_recvmmsg function in net/socket.c in the Linux
    kernel allowed remote attackers to execute arbitrary
    code via vectors involving a recvmmsg system call that
    was mishandled during error processing (bnc#1003077).

  - CVE-2017-5576: Integer overflow in the vc4_get_bcl
    function in drivers/gpu/drm/vc4/vc4_gem.c in the
    VideoCore DRM driver in the Linux kernel allowed local
    users to cause a denial of service or possibly have
    unspecified other impact via a crafted size value in a
    VC4_SUBMIT_CL ioctl call (bnc#1021294).

  - CVE-2017-5577: The vc4_get_bcl function in
    drivers/gpu/drm/vc4/vc4_gem.c in the VideoCore DRM
    driver in the Linux kernel did not set an errno value
    upon certain overflow detections, which allowed local
    users to cause a denial of service (incorrect pointer
    dereference and OOPS) via inconsistent size values in a
    VC4_SUBMIT_CL ioctl call (bnc#1021294).

  - CVE-2017-5551: The simple_set_acl function in
    fs/posix_acl.c in the Linux kernel preserved the setgid
    bit during a setxattr call involving a tmpfs filesystem,
    which allowed local users to gain group privileges by
    leveraging the existence of a setgid program with
    restrictions on execute permissions. (bnc#1021258).

  - CVE-2017-2583: The load_segment_descriptor
    implementation in arch/x86/kvm/emulate.c in the Linux
    kernel improperly emulated a 'MOV SS, NULL selector'
    instruction, which allowed guest OS users to cause a
    denial of service (guest OS crash) or gain guest OS
    privileges via a crafted application (bnc#1020602).

  - CVE-2017-2584: arch/x86/kvm/emulate.c in the Linux
    kernel allowed local users to obtain sensitive
    information from kernel memory or cause a denial of
    service (use-after-free) via a crafted application that
    leverages instruction emulation for fxrstor, fxsave,
    sgdt, and sidt (bnc#1019851).

  - CVE-2015-8709: kernel/ptrace.c in the Linux kernel
    mishandled uid and gid mappings, which allowed local
    users to gain privileges by establishing a user
    namespace, waiting for a root process to enter that
    namespace with an unsafe uid or gid, and then using the
    ptrace system call. NOTE: the vendor states 'there is no
    kernel bug here' (bnc#1010933).

  - CVE-2016-9806: Race condition in the netlink_dump
    function in net/netlink/af_netlink.c in the Linux kernel
    allowed local users to cause a denial of service (double
    free) or possibly have unspecified other impact via a
    crafted application that made sendmsg system calls,
    leading to a free operation associated with a new dump
    that started earlier than anticipated (bnc#1013540).

  - CVE-2017-5897: fixed a bug in the Linux kernel IPv6
    implementation which allowed remote attackers to trigger
    an out-of-bounds access, leading to a denial-of-service
    attack (bnc#1023762).

  - CVE-2017-5970: Fixed a possible denial-of-service that
    could have been triggered by sending bad IP options on a
    socket (bsc#1024938).

  - CVE-2017-5986: an application could have triggered a
    BUG_ON() in sctp_wait_for_sndbuf() if the socket TX
    buffer was full, a thread was waiting on it to queue
    more data, and meanwhile another thread peeled off the
    association being used by the first thread
    (bsc#1025235). The following non-security bugs were
    fixed :

  - 8250: fintek: rename IRQ_MODE macro (boo#1009546).

  - acpi: nfit, libnvdimm: fix / harden ars_status output
    length handling (bsc#1023175).

  - acpi: nfit: fix bus vs dimm confusion in xlat_status
    (bsc#1023175).

  - acpi: nfit: validate ars_status output buffer size
    (bsc#1023175).

  - arm64: numa: fix incorrect log for memory-less node
    (bsc#1019631).

  - asoc: cht_bsw_rt5645: Fix leftover kmalloc
    (bsc#1010690).

  - asoc: rt5670: add HS ground control (bsc#1016250).

  - bcache: Make gc wakeup sane, remove set_task_state()
    (bsc#1021260).

  - bcache: partition support: add 16 minors per bcacheN
    device (bsc#1019784).

  - blk-mq: Allow timeouts to run while queue is freezing
    (bsc#1020817).

  - blk-mq: Always schedule hctx->next_cpu (bsc#1020817).

  - blk-mq: Avoid memory reclaim when remapping queues
    (bsc#1020817).

  - blk-mq: Fix failed allocation path when mapping queues
    (bsc#1020817).

  - blk-mq: do not overwrite rq->mq_ctx (bsc#1020817).

  - blk-mq: improve warning for running a queue on the wrong
    CPU (bsc#1020817).

  - block: Change extern inline to static inline
    (bsc#1023175).

  - bluetooth: btmrvl: fix hung task warning dump
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

  - btrfs: fix btrfs_compat_ioctl failures on non-compat
    ioctls (bsc#1018100).

  - btrfs: fix inode leak on failure to setup whiteout inode
    in rename (bsc#1020975).

  - btrfs: fix lockdep warning about log_mutex
    (bsc#1021455).

  - btrfs: fix lockdep warning on deadlock against an
    inode's log mutex (bsc#1021455).

  - btrfs: fix number of transaction units for renames with
    whiteout (bsc#1020975).

  - btrfs: increment ctx->pos for every emitted or skipped
    dirent in readdir (bsc#981709).

  - btrfs: incremental send, fix invalid paths for rename
    operations (bsc#1018316).

  - btrfs: incremental send, fix premature rmdir operations
    (bsc#1018316).

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

  - ceph: fix bad endianness handling in
    parse_reply_info_extra (bsc#1020488).

  - clk: xgene: Add PMD clock (bsc#1019351).

  - clk: xgene: Do not call __pa on ioremaped address
    (bsc#1019351).

  - clk: xgene: Remove CLK_IS_ROOT (bsc#1019351).

  - config: enable CONFIG_OCFS2_DEBUG_MASKLOG for ocfs2
    (bsc#1015038)

  - config: enable Ceph kernel client modules for ppc64le

  - config: enable Ceph kernel client modules for s390x

  - crypto: FIPS - allow tests to be disabled in FIPS mode
    (bsc#1018913).

  - crypto: drbg - do not call drbg_instantiate in healt
    test (bsc#1018913).

  - crypto: drbg - remove FIPS 140-2 continuous test
    (bsc#1018913).

  - crypto: qat - fix bar discovery for c62x (bsc#1021251).

  - crypto: qat - zero esram only for DH85x devices
    (bsc#1021248).

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

  - drivers: hv: Introduce a policy for controlling channel
    affinity.

  - drivers: hv: balloon: Add logging for dynamic memory
    operations.

  - drivers: hv: balloon: Disable hot add when
    CONFIG_MEMORY_HOTPLUG is not set.

  - drivers: hv: balloon: Fix info request to show max page
    count.

  - drivers: hv: balloon: Use available memory value in
    pressure report.

  - drivers: hv: balloon: account for gaps in hot add
    regions.

  - drivers: hv: balloon: keep track of where ha_region
    starts.

  - drivers: hv: balloon: replace ha_region_mutex with
    spinlock.

  - drivers: hv: cleanup vmbus_open() for wrap around
    mappings.

  - drivers: hv: do not leak memory in
    vmbus_establish_gpadl().

  - drivers: hv: get rid of id in struct vmbus_channel.

  - drivers: hv: get rid of redundant messagecount in
    create_gpadl_header().

  - drivers: hv: get rid of timeout in vmbus_open().

  - drivers: hv: make VMBus bus ids persistent.

  - drivers: hv: ring_buffer: count on wrap around mappings
    in get_next_pkt_raw() (v2).

  - drivers: hv: ring_buffer: use wrap around mappings in
    hv_copy{from, to}_ringbuffer().

  - drivers: hv: ring_buffer: wrap around mappings for ring
    buffers.

  - drivers: hv: utils: Check VSS daemon is listening before
    a hot backup.

  - drivers: hv: utils: Continue to poll VSS channel after
    handling requests.

  - drivers: hv: utils: Fix the mapping between host version
    and protocol to use.

  - drivers: hv: utils: reduce HV_UTIL_NEGO_TIMEOUT timeout.

  - drivers: hv: vmbus: Base host signaling strictly on the
    ring state.

  - drivers: hv: vmbus: Enable explicit signaling policy for
    NIC channels.

  - drivers: hv: vmbus: Implement a mechanism to tag the
    channel for low latency.

  - drivers: hv: vmbus: Make mmio resource local.

  - drivers: hv: vmbus: On the read path cleanup the logic
    to interrupt the host.

  - drivers: hv: vmbus: On write cleanup the logic to
    interrupt the host.

  - drivers: hv: vmbus: Reduce the delay between retries in
    vmbus_post_msg().

  - drivers: hv: vmbus: finally fix
    hv_need_to_signal_on_read().

  - drivers: hv: vmbus: fix the race when querying and
    updating the percpu list.

  - drivers: hv: vmbus: suppress some 'hv_vmbus: Unknown
    GUID' warnings.

  - drivers: hv: vss: Improve log messages.

  - drivers: hv: vss: Operation timeouts should match host
    expectation.

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

  - drivers: net: xgene: Fix MSS programming (bsc#1019351).

  - drivers: net: xgene: fix build after change_mtu function
    change (bsc#1019351).

  - drivers: net: xgene: fix: Coalescing values for v2
    hardware (bsc#1019351).

  - drivers: net: xgene: fix: Disable coalescing on v1
    hardware (bsc#1019351).

  - drivers: net: xgene: fix: RSS for non-TCP/UDP
    (bsc#1019351).

  - drivers: net: xgene: fix: Use GPIO to get link status
    (bsc#1019351).

  - drivers: net: xgene: uninitialized variable in
    xgene_enet_free_pagepool() (bsc#1019351).

  - drm: Delete previous two fixes for i915 (bsc#1019061).
    These upstream fixes brought some regressions, so better
    to revert for now.

  - drm: Disable
    patches.drivers/drm-i915-Exit-cherryview_irq_handler-aft
    er-one-pass The patch seems leading to the instability
    on Wyse box (bsc#1015367).

  - drm: Fix broken VT switch with video=1366x768 option
    (bsc#1018358).

  - drm: Use u64 for intermediate dotclock calculations
    (bnc#1006472).

  - drm: i915: Do not init hpd polling for vlv and chv from
    runtime_suspend() (bsc#1014120).

  - drm: i915: Fix PCODE polling during CDCLK change
    notification (bsc#1015367).

  - drm: i915: Fix watermarks for VLV/CHV (bsc#1011176).

  - drm: i915: Force VDD off on the new power seqeuencer
    before starting to use it (bsc#1009674).

  - drm: i915: Mark CPU cache as dirty when used for
    rendering (bsc#1015367).

  - drm: i915: Mark i915_hpd_poll_init_work as static
    (bsc#1014120).

  - drm: i915: Prevent PPS stealing from a normal DP port on
    VLV/CHV (bsc#1019061).

  - drm: i915: Prevent enabling hpd polling in late suspend
    (bsc#1014120).

  - drm: i915: Restore PPS HW state from the encoder resume
    hook (bsc#1019061).

  - drm: i915: Workaround for DP DPMS D3 on Dell monitor
    (bsc#1019061).

  - drm: vc4: Fix an integer overflow in temporary
    allocation layout (bsc#1021294).

  - drm: vc4: Return -EINVAL on the overflow checks failing
    (bsc#1021294).

  - drm: virtio-gpu: get the fb from the plane state for
    atomic updates (bsc#1023101).

  - edac: xgene: Fix spelling mistake in error messages
    (bsc#1019351).

  - efi: libstub: Move Graphics Output Protocol handling to
    generic code (bnc#974215).

  - fbcon: Fix vc attr at deinit (bsc#1000619).

  - fs: nfs: avoid including 'mountproto=' with no protocol
    in /proc/mounts (bsc#1019260).

  - gpio: xgene: make explicitly non-modular (bsc#1019351).

  - hv: acquire vmbus_connection.channel_mutex in
    vmbus_free_channels().

  - hv: change clockevents unbind tactics.

  - hv: do not reset hv_context.tsc_page on crash.

  - hv_netvsc: Add handler for physical link speed change.

  - hv_netvsc: Add query for initial physical link speed.

  - hv_netvsc: Implement batching of receive completions.

  - hv_netvsc: Revert 'make inline functions static'.

  - hv_netvsc: Revert 'report vmbus name in ethtool'.

  - hv_netvsc: add ethtool statistics for tx packet issues.

  - hv_netvsc: count multicast packets received.

  - hv_netvsc: dev hold/put reference to VF.

  - hv_netvsc: fix a race between netvsc_send() and
    netvsc_init_buf().

  - hv_netvsc: fix comments.

  - hv_netvsc: fix rtnl locking in callback.

  - hv_netvsc: improve VF device matching.

  - hv_netvsc: init completion during alloc.

  - hv_netvsc: make RSS hash key static.

  - hv_netvsc: make device_remove void.

  - hv_netvsc: make inline functions static.

  - hv_netvsc: make netvsc_destroy_buf void.

  - hv_netvsc: make variable local.

  - hv_netvsc: rearrange start_xmit.

  - hv_netvsc: refactor completion function.

  - hv_netvsc: remove VF in flight counters.

  - hv_netvsc: remove excessive logging on MTU change.

  - hv_netvsc: report vmbus name in ethtool.

  - hv_netvsc: simplify callback event code.

  - hv_netvsc: style cleanups.

  - hv_netvsc: use ARRAY_SIZE() for NDIS versions.

  - hv_netvsc: use RCU to protect vf_netdev.

  - hv_netvsc: use consume_skb.

  - hv_netvsc: use kcalloc.

  - hyperv: Fix spelling of HV_UNKOWN.

  - i2c: designware-baytrail: Disallow the CPU to enter C6
    or C7 while holding the punit semaphore (bsc#1011913).

  - i2c: designware: Implement support for SMBus block read
    and write (bsc#1019351).

  - i2c: designware: fix wrong Tx/Rx FIFO for ACPI
    (bsc#1019351).

  - i2c: xgene: Fix missing code of DTB support
    (bsc#1019351).

  - i40e: Be much more verbose about what we can and cannot
    offload (bsc#985561).

  - ibmveth: calculate gso_segs for large packets
    (bsc#1019148).

  - ibmveth: check return of skb_linearize in
    ibmveth_start_xmit (bsc#1019148).

  - ibmveth: consolidate kmalloc of array, memset 0 to
    kcalloc (bsc#1019148).

  - ibmveth: set correct gso_size and gso_type
    (bsc#1019148).

  - igb: Workaround for igb i210 firmware issue
    (bsc#1009911).

  - igb: add i211 to i210 PHY workaround (bsc#1009911).

  - input: i8042: Trust firmware a bit more when probing on
    X86 (bsc#1011660).

  - intel_idle: Add KBL support (bsc#1016884).

  - ip6_gre: fix ip6gre_err() invalid reads (CVE-2017-5897,
    bsc#1023762).

  - ipc: msg, make msgrcv work with LONG_MIN (bnc#1005918).

  - iwlwifi: Expose the default fallback ucode API to module
    info (boo#1021082, boo#1023884).

  - kgraft: iscsi-target: Do not block kGraft in iscsi_np
    kthread (bsc#1010612).

  - kgraft: xen: Do not block kGraft in xenbus kthread
    (bsc#1017410).

  - libnvdimm: pfn: fix align attribute (bsc#1023175).

  - mailbox: xgene-slimpro: Fix wrong test for devm_kzalloc
    (bsc#1019351).

  - md linear: fix a race between linear_add() and
    linear_congested() (bsc#1018446).

  - md-cluster: convert the completion to wait queue.

  - md-cluster: protect md_find_rdev_nr_rcu with rcu lock.

  - md: ensure md devices are freed before module is
    unloaded (bsc#1022304).

  - md: fix refcount problem on mddev when stopping array
    (bsc#1022304).

  - misc: genwqe: ensure zero initialization.

  - mm: do not loop on GFP_REPEAT high order requests if
    there is no reclaim progress (bnc#1013000).

  - mm: memcg: do not retry precharge charges (bnc#1022559).

  - mm: page_alloc: fix check for NULL preferred_zone
    (bnc#971975 VM performance -- page allocator).

  - mm: page_alloc: fix fast-path race with cpuset update or
    removal (bnc#971975 VM performance -- page allocator).

  - mm: page_alloc: fix premature OOM when racing with
    cpuset mems update (bnc#971975 VM performance -- page
    allocator).

  - mm: page_alloc: keep pcp count and list contents in sync
    if struct page is corrupted (bnc#971975 VM performance
    -- page allocator).

  - mm: page_alloc: move cpuset seqcount checking to
    slowpath (bnc#971975 VM performance -- page allocator).

  - mmc: sdhci-of-arasan: Remove no-hispd and no-cmd23
    quirks for sdhci-arasan4.9a (bsc#1019351).

  - mwifiex: add missing check for PCIe8997 chipset
    (bsc#1018813).

  - mwifiex: fix IBSS data path issue (bsc#1018813).

  - mwifiex: fix PCIe register information for 8997 chipset
    (bsc#1018813).

  - net: af_iucv: do not use paged skbs for TX on
    HiperSockets (bnc#1020945, LTC#150566).

  - net: ethernet: apm: xgene: use phydev from struct
    net_device (bsc#1019351).

  - net: ethtool: Initialize buffer when querying device
    channel settings (bsc#969479).

  - net: hyperv: avoid uninitialized variable.

  - net: implement netif_cond_dbg macro (bsc#1019168).

  - net: remove useless memset's in drivers get_stats64
    (bsc#1019351).

  - net: xgene: avoid bogus maybe-uninitialized warning
    (bsc#1019351).

  - net: xgene: fix backward compatibility fix
    (bsc#1019351).

  - net: xgene: fix error handling during reset
    (bsc#1019351).

  - net: xgene: move xgene_cle_ptree_ewdn data off stack
    (bsc#1019351).

  - netvsc: Remove mistaken udp.h inclusion.

  - netvsc: add rcu_read locking to netvsc callback.

  - netvsc: fix checksum on UDP IPV6.

  - netvsc: reduce maximum GSO size.

  - nfit: fail DSMs that return non-zero status by default
    (bsc#1023175).

  - nfsv4: Cap the transport reconnection timer at 1/2 lease
    period (bsc#1014410).

  - nfsv4: Cleanup the setting of the nfs4 lease period
    (bsc#1014410).

  - nvdimm: kabi protect nd_cmd_out_size() (bsc#1023175).

  - nvme: apply DELAY_BEFORE_CHK_RDY quirk at probe time too
    (bsc#1020685).

  - ocfs2: fix deadlock on mmapped page in
    ocfs2_write_begin_nolock() (bnc#921494).

  - pci: Add devm_request_pci_bus_resources() (bsc#1019351).

  - pci: generic: Fix pci_remap_iospace() failure path
    (bsc#1019630).

  - pci: hv: Allocate physically contiguous hypercall params
    buffer.

  - pci: hv: Fix hv_pci_remove() for hot-remove.

  - pci: hv: Handle hv_pci_generic_compl() error case.

  - pci: hv: Handle vmbus_sendpacket() failure in
    hv_compose_msi_msg().

  - pci: hv: Make unnecessarily global IRQ masking functions
    static.

  - pci: hv: Remove the unused 'wrk' in struct
    hv_pcibus_device.

  - pci: hv: Use list_move_tail() instead of list_del() +
    list_add_tail().

  - pci: hv: Use pci_function_description in struct
    definitions.

  - pci: hv: Use the correct buffer size in
    new_pcichild_device().

  - pci: hv: Use zero-length array in struct pci_packet.

  - pci: include header file (bsc#964944).

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

  - power: reset: xgene-reboot: Unmap region obtained by
    of_iomap (bsc#1019351).

  - powerpc: fadump: Fix the race in crash_fadump()
    (bsc#1022971).

  - qeth: check not more than 16 SBALEs on the completion
    queue (bnc#1009718, LTC#148203).

  - raid1: Fix a regression observed during the rebuilding
    of degraded MDRAID VDs (bsc#1020048).

  - raid1: ignore discard error (bsc#1017164).

  - reiserfs: fix race in prealloc discard (bsc#987576).

  - rpm: kernel-binary.spec.in: Export a make-stderr.log
    file (bsc#1012422)

  - rpm: kernel-binary.spec.in: Fix installation of
    /etc/uefi/certs (bsc#1019594)

  - rtc: cmos: Clear ACPI-driven alarms upon resume
    (bsc#1022429).

  - rtc: cmos: Do not enable interrupts in the middle of the
    interrupt handler (bsc#1022429).

  - rtc: cmos: Restore alarm after resume (bsc#1022429).

  - rtc: cmos: avoid unused function warning (bsc#1022429).

  - s390: Fix invalid domain response handling
    (bnc#1009718).

  - s390: cpuinfo: show maximum thread id (bnc#1009718,
    LTC#148580).

  - s390: sysinfo: show partition extended name and UUID if
    available (bnc#1009718, LTC#150160).

  - s390: time: LPAR offset handling (bnc#1009718,
    LTC#146920).

  - s390: time: move PTFF definitions (bnc#1009718,
    LTC#146920).

  - sched: Allow hotplug notifiers to be setup early
    (bnc#1022476).

  - sched: Make wake_up_nohz_cpu() handle CPUs going offline
    (bnc#1022476).

  - sched: core, x86/topology: Fix NUMA in package topology
    bug (bnc#1022476).

  - sched: core: Fix incorrect utilization accounting when
    switching to fair class (bnc#1022476).

  - sched: core: Fix set_user_nice() (bnc#1022476).

  - sched: cputime: Add steal time support to full dynticks
    CPU time accounting (bnc#1022476).

  - sched: cputime: Fix prev steal time accouting during CPU
    hotplug (bnc#1022476).

  - sched: deadline: Always calculate end of period on
    sched_yield() (bnc#1022476).

  - sched: deadline: Fix a bug in dl_overflow()
    (bnc#1022476).

  - sched: deadline: Fix lock pinning warning during CPU
    hotplug (bnc#1022476).

  - sched: deadline: Fix wrap-around in DL heap
    (bnc#1022476).

  - sched: fair: Avoid using decay_load_missed() with a
    negative value (bnc#1022476).

  - sched: fair: Fix fixed point arithmetic width for shares
    and effective load (bnc#1022476).

  - sched: fair: Fix load_above_capacity fixed point
    arithmetic width (bnc#1022476).

  - sched: fair: Fix min_vruntime tracking (bnc#1022476).

  - sched: fair: Fix the wrong throttled clock time for
    cfs_rq_clock_task() (bnc#1022476).

  - sched: fair: Improve PELT stuff some more (bnc#1022476).

  - sched: rt, sched/dl: Do not push if task's scheduling
    class was changed (bnc#1022476).

  - sched: rt: Fix PI handling vs. sched_setscheduler()
    (bnc#1022476).

  - sched: rt: Kick RT bandwidth timer immediately on start
    up (bnc#1022476).

  - scsi: Add 'AIX VDASD' to blacklist (bsc#1006469).

  - scsi: Modify HITACHI OPEN-V blacklist entry
    (bsc#1006469).

  - scsi: bfa: Increase requested firmware version to
    3.2.5.1 (bsc#1013273).

  - scsi: storvsc: Payload buffer incorrectly sized for 32
    bit kernels.

  - scsi_dh_alua: uninitialized variable in alua_rtpg()
    (bsc#1012910).

  - sctp: avoid BUG_ON on sctp_wait_for_sndbuf
    (CVE-2017-5986, bsc#1025235).

  - sd: always scan VPD pages if thin provisioning is
    enabled (bsc#1013792).

  - serial: 8250: Integrate Fintek into 8250_base
    (boo#1016979). Update config files to change
    CONFIG_SERIAL_8250_FINTEK to boolean accordingly, too.
    Also, the corresponding entry got removed from
    supported.conf.

  - serial: 8250_fintek: fix the mismatched IRQ mode
    (boo#1009546).

  - serial: Update metadata for serial fixes (bsc#1013001)

  - ses: Fix SAS device detection in enclosure
    (bsc#1016403).

  - sfc: reduce severity of PIO buffer alloc failures
    (bsc#1019168).

  - sfc: refactor debug-or-warnings printks (bsc#1019168).

  - sunrpc: Fix reconnection timeouts (bsc#1014410).

  - sunrpc: Limit the reconnect backoff timer to the max RPC
    message timeout (bsc#1014410).

  - supported.conf: Support Marvell WiFi/BT SDIO and
    pinctrl-cherrytrail (bsc#1018813)

  - supported.conf: delete xilinx/ll_temac (bsc#1011602)

  - target: add XCOPY target/segment desc sense codes
    (bsc#991273).

  - target: bounds check XCOPY segment descriptor list
    (bsc#991273).

  - target: bounds check XCOPY total descriptor list length
    (bsc#991273).

  - target: check XCOPY segment descriptor CSCD IDs
    (bsc#1017170).

  - target: check for XCOPY parameter truncation
    (bsc#991273).

  - target: return UNSUPPORTED TARGET/SEGMENT DESC TYPE CODE
    sense (bsc#991273).

  - target: simplify XCOPY wwn->se_dev lookup helper
    (bsc#991273).

  - target: support XCOPY requests without parameters
    (bsc#991273).

  - target: use XCOPY TOO MANY TARGET DESCRIPTORS sense
    (bsc#991273).

  - target: use XCOPY segment descriptor CSCD IDs
    (bsc#1017170).

  - tools: hv: Enable network manager for bonding scripts on
    RHEL.

  - tools: hv: fix a compile warning in snprintf.

  - tools: hv: kvp: configurable external scripts path.

  - tools: hv: kvp: ensure kvp device fd is closed on exec.

  - tools: hv: remove unnecessary header files and netlink
    related code.

  - tools: hv: remove unnecessary link flag.

  - tty: n_hdlc, fix lockdep false positive (bnc#1015840).

  - uvcvideo: uvc_scan_fallback() for webcams with broken
    chain (bsc#1021474).

  - vmbus: make sysfs names consistent with PCI.

  - x86: MCE: Dump MCE to dmesg if no consumers
    (bsc#1013994).

  - x86: hyperv: Handle unknown NMIs on one CPU when
    unknown_nmi_panic.

  - xfs: don't allow di_size with high bit set
    (bsc#1024234).

  - xfs: exclude never-released buffers from buftarg I/O
    accounting (bsc#1024508).

  - xfs: fix broken multi-fsb buffer logging (bsc#1024081).

  - xfs: fix buffer overflow
    dm_get_dirattrs/dm_get_dirattrs2 (bsc#989056).

  - xfs: fix up xfs_swap_extent_forks inline extent handling
    (bsc#1023888).

  - xfs: track and serialize in-flight async buffers against
    unmount (bsc#1024508).

  - xfs: track and serialize in-flight async buffers against
    unmount - kABI (bsc#1024508).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1007729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1022304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1022429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1022476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1022547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1022559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1022971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1025235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8709.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7117.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9806.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2583.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2584.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5551.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5576.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5577.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5897.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5970.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5986.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170575-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d9dd818"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP2:zypper in -t patch
SUSE-SLE-WE-12-SP2-2017-300=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-300=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-300=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-300=1

SUSE Linux Enterprise Live Patching 12:zypper in -t patch
SUSE-SLE-Live-Patching-12-2017-300=1

SUSE Linux Enterprise High Availability 12-SP2:zypper in -t patch
SUSE-SLE-HA-12-SP2-2017-300=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-300=1

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2017-300=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-4.4.49-92.11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-base-4.4.49-92.11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-base-debuginfo-4.4.49-92.11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-debuginfo-4.4.49-92.11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-debugsource-4.4.49-92.11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-devel-4.4.49-92.11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-syms-4.4.49-92.11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-4.4.49-92.11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-debuginfo-4.4.49-92.11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-debugsource-4.4.49-92.11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-devel-4.4.49-92.11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-extra-4.4.49-92.11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-4.4.49-92.11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-syms-4.4.49-92.11.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
