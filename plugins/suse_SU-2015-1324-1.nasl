#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1324-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(85180);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/11/14 14:25:31 $");

  script_cve_id("CVE-2014-9728", "CVE-2014-9729", "CVE-2014-9730", "CVE-2014-9731", "CVE-2015-1805", "CVE-2015-3212", "CVE-2015-4036", "CVE-2015-4167", "CVE-2015-4692", "CVE-2015-5364", "CVE-2015-5366");
  script_bugtraq_id(74664, 74951, 74963, 74964, 75001, 75142, 75510);
  script_osvdb_id(119615, 122192, 122921, 122965, 122966, 122967, 122968, 123200, 123996, 124240);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : SUSE Linux Enterprise 12 kernel (SUSE-SU-2015:1324-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 kernel was updated to 3.12.44 to receive
various security and bugfixes.

These features were added :

  - mpt2sas: Added Reply Descriptor Post Queue (RDPQ) Array
    support (bsc#854824).

  - mpt3sas: Bump mpt3sas driver version to 04.100.00.00
    (bsc#854817).

Following security bugs were fixed :

  - CVE-2015-1805: iov overrun for failed atomic copy could
    have lead to DoS or privilege escalation (bsc#933429).

  - CVE-2015-3212: A race condition in the way the Linux
    kernel handled lists of associations in SCTP sockets
    could have lead to list corruption and kernel panics
    (bsc#936502).

  - CVE-2015-4036: DoS via memory corruption in vhost/scsi
    driver (bsc#931988).

  - CVE-2015-4167: Linux kernel built with the UDF file
    system(CONFIG_UDF_FS) support was vulnerable to a crash.
    It occurred while fetching inode information from a
    corrupted/malicious udf file system image (bsc#933907).

  - CVE-2015-4692: DoS via NULL pointer dereference in
    kvm_apic_has_events function (bsc#935542).

  - CVE-2015-5364: Remote DoS via flood of UDP packets with
    invalid checksums (bsc#936831).

  - CVE-2015-5366: Remote DoS of EPOLLET epoll applications
    via flood of UDP packets with invalid checksums
    (bsc#936831).

Security issues already fixed in the previous update but not
referenced by CVE :

  - CVE-2014-9728: Kernel built with the UDF file
    system(CONFIG_UDF_FS) support were vulnerable to a crash
    (bsc#933904).

  - CVE-2014-9729: Kernel built with the UDF file
    system(CONFIG_UDF_FS) support were vulnerable to a crash
    (bsc#933904).

  - CVE-2014-9730: Kernel built with the UDF file
    system(CONFIG_UDF_FS) support were vulnerable to a crash
    (bsc#933904).

  - CVE-2014-9731: Kernel built with the UDF file
    system(CONFIG_UDF_FS) support were vulnerable to
    information leakage (bsc#933896).

The following non-security bugs were fixed :

  - ALSA: hda - add codec ID for Skylake display audio codec
    (bsc#936556).

  - ALSA: hda/hdmi - apply Haswell fix-ups to Skylake
    display codec (bsc#936556).

  - ALSA: hda_controller: Separate stream_tag for input and
    output streams (bsc#936556).

  - ALSA: hda_intel: add AZX_DCAPS_I915_POWERWELL for SKL
    and BSW (bsc#936556).

  - ALSA: hda_intel: apply the Separate stream_tag for
    Skylake (bsc#936556).

  - ALSA: hda_intel: apply the Separate stream_tag for
    Sunrise Point (bsc#936556).

  - Btrfs: Handle unaligned length in extent_same
    (bsc#937609).

  - Btrfs: add missing inode item update in fallocate()
    (bsc#938023).

  - Btrfs: check pending chunks when shrinking fs to avoid
    corruption (bsc#936445).

  - Btrfs: do not update mtime/ctime on deduped inodes
    (bsc#937616).

  - Btrfs: fix block group ->space_info NULL pointer
    dereference (bsc#935088).

  - Btrfs: fix clone / extent-same deadlocks (bsc#937612).

  - Btrfs: fix deadlock with extent-same and readpage
    (bsc#937612).

  - Btrfs: fix fsync data loss after append write
    (bsc#936446).

  - Btrfs: fix hang during inode eviction due to concurrent
    readahead (bsc#935085).

  - Btrfs: fix memory leak in the extent_same ioctl
    (bsc#937613).

  - Btrfs: fix race when reusing stale extent buffers that
    leads to BUG_ON (bsc#926369).

  - Btrfs: fix use after free when close_ctree frees the
    orphan_rsv (bsc#938022).

  - Btrfs: pass unaligned length to btrfs_cmp_data()
    (bsc#937609).

  - Btrfs: provide super_operations->inode_get_dev
    (bsc#927455).

  - Drivers: hv: balloon: check if ha_region_mutex was
    acquired in MEM_CANCEL_ONLINE case.

  - Drivers: hv: fcopy: process deferred messages when we
    complete the transaction.

  - Drivers: hv: fcopy: rename fcopy_work ->
    fcopy_timeout_work.

  - Drivers: hv: fcopy: set .owner reference for file
    operations.

  - Drivers: hv: fcopy: switch to using the
    hvutil_device_state state machine.

  - Drivers: hv: hv_balloon: correctly handle
    num_pages>INT_MAX case.

  - Drivers: hv: hv_balloon: correctly handle val.freeram
    lower than num_pages case.

  - Drivers: hv: hv_balloon: do not lose memory when
    onlining order is not natural.

  - Drivers: hv: hv_balloon: do not online pages in offline
    blocks.

  - Drivers: hv: hv_balloon: eliminate jumps in piecewiese
    linear floor function.

  - Drivers: hv: hv_balloon: eliminate the trylock path in
    acquire/release_region_mutex.

  - Drivers: hv: hv_balloon: keep locks balanced on
    add_memory() failure.

  - Drivers: hv: hv_balloon: refuse to balloon below the
    floor.

  - Drivers: hv: hv_balloon: report offline pages as being
    used.

  - Drivers: hv: hv_balloon: survive ballooning request with
    num_pages=0.

  - Drivers: hv: kvp: move poll_channel() to hyperv_vmbus.h.

  - Drivers: hv: kvp: rename kvp_work -> kvp_timeout_work.

  - Drivers: hv: kvp: reset kvp_context.

  - Drivers: hv: kvp: switch to using the
    hvutil_device_state state machine.

  - Drivers: hv: util: Fix a bug in the KVP code. reapply
    upstream change ontop of v3.12-stable change

  - Drivers: hv: util: On device remove, close the channel
    after de-initializing the service.

  - Drivers: hv: util: introduce hv_utils_transport
    abstraction.

  - Drivers: hv: util: introduce state machine for util
    drivers.

  - Drivers: hv: util: move kvp/vss function declarations to
    hyperv_vmbus.h.

  - Drivers: hv: vmbus: Add device and vendor ID to vmbus
    devices.

  - Drivers: hv: vmbus: Add support for VMBus panic notifier
    handler (bsc#934160).

  - Drivers: hv: vmbus: Add support for the NetworkDirect
    GUID.

  - Drivers: hv: vmbus: Correcting truncation error for
    constant HV_CRASH_CTL_CRASH_NOTIFY (bsc#934160).

  - Drivers: hv: vmbus: Export the
    vmbus_sendpacket_pagebuffer_ctl().

  - Drivers: hv: vmbus: Fix a bug in rescind processing in
    vmbus_close_internal().

  - Drivers: hv: vmbus: Fix a siganlling host signalling
    issue.

  - Drivers: hv: vmbus: Get rid of some unnecessary
    messages.

  - Drivers: hv: vmbus: Get rid of some unused definitions.

  - Drivers: hv: vmbus: Handle both rescind and offer
    messages in the same context.

  - Drivers: hv: vmbus: Implement the protocol for tearing
    down vmbus state.

  - Drivers: hv: vmbus: Introduce a function to remove a
    rescinded offer.

  - Drivers: hv: vmbus: Perform device register in the
    per-channel work element.

  - Drivers: hv: vmbus: Permit sending of packets without
    payload.

  - Drivers: hv: vmbus: Properly handle child device remove.

  - Drivers: hv: vmbus: Remove the channel from the channel
    list(s) on failure.

  - Drivers: hv: vmbus: Suport an API to send packet with
    additional control.

  - Drivers: hv: vmbus: Suport an API to send pagebuffers
    with additional control.

  - Drivers: hv: vmbus: Teardown clockevent devices on
    module unload.

  - Drivers: hv: vmbus: Teardown synthetic interrupt
    controllers on module unload.

  - Drivers: hv: vmbus: Use a round-robin algorithm for
    picking the outgoing channel.

  - Drivers: hv: vmbus: Use the vp_index map even for
    channels bound to CPU 0.

  - Drivers: hv: vmbus: avoid double kfree for device_obj.

  - Drivers: hv: vmbus: briefly comment num_sc and next_oc.

  - Drivers: hv: vmbus: decrease num_sc on subchannel
    removal.

  - Drivers: hv: vmbus: distribute subchannels among all
    vcpus.

  - Drivers: hv: vmbus: do cleanup on all vmbus_open()
    failure paths.

  - Drivers: hv: vmbus: introduce vmbus_acpi_remove.

  - Drivers: hv: vmbus: kill tasklets on module unload.

  - Drivers: hv: vmbus: move init_vp_index() call to
    vmbus_process_offer().

  - Drivers: hv: vmbus: prevent cpu offlining on newer
    hypervisors.

  - Drivers: hv: vmbus: rename channel work queues.

  - Drivers: hv: vmbus: teardown hv_vmbus_con workqueue and
    vmbus_connection pages on shutdown.

  - Drivers: hv: vmbus: unify calls to percpu_channel_enq().

  - Drivers: hv: vmbus: unregister panic notifier on module
    unload.

  - Drivers: hv: vmbus:Update preferred vmbus protocol
    version to windows 10.

  - Drivers: hv: vss: process deferred messages when we
    complete the transaction.

  - Drivers: hv: vss: switch to using the
    hvutil_device_state state machine.

  - Enable CONFIG_BRIDGE_NF_EBTABLES on s390x (bsc#936012)

  - Fix connection reuse when sk_error_report is used
    (bsc#930972).

  - GHES: Carve out error queueing in a separate function
    (bsc#917630).

  - GHES: Carve out the panic functionality (bsc#917630).

  - GHES: Elliminate double-loop in the NMI handler
    (bsc#917630).

  - GHES: Make NMI handler have a single reader
    (bsc#917630).

  - GHES: Panic right after detection (bsc#917630).

  - IB/mlx4: Fix wrong usage of IPv4 protocol for multicast
    attach/detach (bsc#918618).

  - Initialize hv_netvsc_packet->xmit_more to avoid transfer
    stalls

  - KVM: PPC: BOOK3S: HV: CMA: Reserve cma region only in
    hypervisor mode (bsc#908491).

  - KVM: s390: virtio-ccw: Handle command rejects
    (bsc#931860).

  - MODSIGN: loading keys from db when SecureBoot disabled
    (bsc#929696).

  - MODSIGN: loading keys from db when SecureBoot disabled
    (bsc#929696).

  - PCI: pciehp: Add hotplug_lock to serialize hotplug
    events (bsc#866911).

  - Revert 'MODSIGN: loading keys from db when SecureBoot
    disabled'. This reverts commit b45412d4, because it
    breaks legacy boot.

  - SUNRPC: Report connection error values to rpc_tasks on
    the pending queue (bsc#930972).

  - Update s390x kabi files with netfilter change
    (bsc#936012)

  - client MUST ignore EncryptionKeyLength if
    CAP_EXTENDED_SECURITY is set (bsc#932348).

  - cpufreq: pcc: Enable autoload of pcc-cpufreq for ACPI
    processors (bsc#933117).

  - dmapi: fix value from newer Linux strnlen_user()
    (bsc#932897).

  - drm/i915/hsw: Fix workaround for server AUX channel
    clock divisor (bsc#935918).

  - drm/i915: Evict CS TLBs between batches (bsc#935918).

  - drm/i915: Fix DDC probe for passive adapters
    (bsc#935918).

  - drm/i915: Handle failure to kick out a conflicting fb
    driver (bsc#935918).

  - drm/i915: drop WaSetupGtModeTdRowDispatch:snb
    (bsc#935918).

  - drm/i915: save/restore GMBUS freq across suspend/resume
    on gen4 (bsc#935918).

  - edd: support original Phoenix EDD 3.0 information
    (bsc#929974).

  - ext4: fix over-defensive complaint after journal abort
    (bsc#935174).

  - fs/cifs: Fix corrupt SMB2 ioctl requests (bsc#931124).

  - ftrace: add oco handling patch (bsc#924526).

  - ftrace: allow architectures to specify ftrace compile
    options (bsc#924526).

  - ftrace: let notrace function attribute disable
    hotpatching if necessary (bsc#924526).

  - hugetlb, kabi: do not account hugetlb pages as
    NR_FILE_PAGES (bsc#930092).

  - hugetlb: do not account hugetlb pages as NR_FILE_PAGES
    (bsc#930092).

  - hv: channel: match var type to return type of
    wait_for_completion.

  - hv: do not schedule new works in
    vmbus_onoffer()/vmbus_onoffer_rescind().

  - hv: hv_balloon: match var type to return type of
    wait_for_completion.

  - hv: hv_util: move vmbus_open() to a later place.

  - hv: hypervvssd: call endmntent before call setmntent
    again.

  - hv: no rmmod for hv_vmbus and hv_utils.

  - hv: remove the per-channel workqueue.

  - hv: run non-blocking message handlers in the dispatch
    tasklet.

  - hv: vmbus: missing curly braces in
    vmbus_process_offer().

  - hv: vmbus_free_channels(): remove the redundant
    free_channel().

  - hv: vmbus_open(): reset the channel state on ENOMEM.

  - hv: vmbus_post_msg: retry the hypercall on some
    transient errors.

  - hv_netvsc: Allocate the receive buffer from the correct
    NUMA node.

  - hv_netvsc: Allocate the sendbuf in a NUMA aware way.

  - hv_netvsc: Clean up two unused variables.

  - hv_netvsc: Cleanup the test for freeing skb when we use
    sendbuf mechanism.

  - hv_netvsc: Define a macro RNDIS_AND_PPI_SIZE.

  - hv_netvsc: Eliminate memory allocation in the packet
    send path.

  - hv_netvsc: Fix a bug in netvsc_start_xmit().

  - hv_netvsc: Fix the packet free when it is in skb
    headroom.

  - hv_netvsc: Implement batching in send buffer.

  - hv_netvsc: Implement partial copy into send buffer.

  - hv_netvsc: Use the xmit_more skb flag to optimize
    signaling the host.

  - hv_netvsc: change member name of struct netvsc_stats.

  - hv_netvsc: introduce netif-msg into netvsc module.

  - hv_netvsc: remove unused variable in netvsc_send().

  - hv_netvsc: remove vmbus_are_subchannels_present() in
    rndis_filter_device_add().

  - hv_netvsc: try linearizing big SKBs before dropping
    them.

  - hv_netvsc: use per_cpu stats to calculate TX/RX data.

  - hv_netvsc: use single existing drop path in
    netvsc_start_xmit.

  - hv_vmbus: Add gradually increased delay for retries in
    vmbus_post_msg().

  - hyperv: Implement netvsc_get_channels() ethool op.

  - hyperv: hyperv_fb: match wait_for_completion_timeout
    return type.

  - iommu/amd: Handle integer overflow in dma_ops_area_alloc
    (bsc#931538).

  - iommu/amd: Handle large pages correctly in
    free_pagetable (bsc#935881).

  - ipr: Increase default adapter init stage change timeout
    (bsc#930579).

  - ipv6: do not delete previously existing ECMP routes if
    add fails (bsc#930399).

  - ipv6: fix ECMP route replacement (bsc#930399).

  - jbd2: improve error messages for inconsistent journal
    heads (bsc#935174).

  - jbd2: revise KERN_EMERG error messages (bsc#935174).

  - kabi/severities: Add s390 symbols allowed to change in
    bsc#931860

  - kabi: only use sops->get_inode_dev with proper fsflag.

  - kernel: add panic_on_warn.

  - kexec: allocate the kexec control page with
    KEXEC_CONTROL_MEMORY_GFP (bsc#928131).

  - kgr: fix redirection on s390x arch (bsc#903279).

  - kgr: move kgr_task_in_progress() to sched.h.

  - kgr: send a fake signal to all blocking tasks.

  - kvm: irqchip: Break up high order allocations of
    kvm_irq_routing_table (bsc#926953).

  - libata: Blacklist queued TRIM on all Samsung 800-series
    (bsc#930599).

  - mei: bus: () can be static.

  - mm, thp: really limit transparent hugepage allocation to
    local node (VM Performance, bsc#931620).

  - mm, thp: respect MPOL_PREFERRED policy with non-local
    node (VM Performance, bsc#931620).

  - mm/mempolicy.c: merge alloc_hugepage_vma to
    alloc_pages_vma (VM Performance, bsc#931620).

  - mm/thp: allocate transparent hugepages on local node (VM
    Performance, bsc#931620).

  - net/mlx4_en: Call register_netdevice in the proper
    location (bsc#858727).

  - net/mlx4_en: Do not attempt to TX offload the outer UDP
    checksum for VXLAN (bsc#858727).

  - net: fib6: fib6_commit_metrics: fix potential NULL
    pointer dereference (bsc#867362).

  - net: introduce netdev_alloc_pcpu_stats() for drivers.

  - net: ipv6: fib: do not sleep inside atomic lock
    (bsc#867362).

  - netdev: set __percpu attribute on
    netdev_alloc_pcpu_stats.

  - netdev_alloc_pcpu_stats: use less common iterator
    variable.

  - netfilter: xt_NFQUEUE: fix --queue-bypass regression
    (bsc#935083)

  - ovl: default permissions (bsc#924071).

  - ovl: move s_stack_depth .

  - powerpc/perf/hv-24x7: use kmem_cache instead of aligned
    stack allocations (bsc#931403).

  - powerpc/pseries: Correct cpu affinity for dlpar added
    cpus (bsc#932967).

  - powerpc: Add VM_FAULT_HWPOISON handling to powerpc page
    fault handler (bsc#929475).

  - powerpc: Fill in si_addr_lsb siginfo field (bsc#929475).

  - powerpc: Simplify do_sigbus (bsc#929475).

  - reiserfs: Fix use after free in journal teardown
    (bsc#927697).

  - rtlwifi: rtl8192cu: Fix kernel deadlock (bsc#927786).

  - s390/airq: add support for irq ranges (bsc#931860).

  - s390/airq: silence lockdep warning (bsc#931860).

  - s390/compat,signal: change return values to -EFAULT
    (bsc#929879).

  - s390/ftrace: hotpatch support for function tracing
    (bsc#924526).

  - s390/irq: improve displayed interrupt order in
    /proc/interrupts (bsc#931860).

  - s390/kernel: use stnsm 255 instead of stosm 0
    (bsc#929879).

  - s390/kgr: reorganize kgr infrastructure in entry64.S.

  - s390/mm: align 64-bit PIE binaries to 4GB (bsc#929879).

  - s390/mm: limit STACK_RND_MASK for compat tasks
    (bsc#929879).

  - s390/rwlock: add missing local_irq_restore calls
    (bsc#929879).

  - s390/sclp_vt220: Fix kernel panic due to early terminal
    input (bsc#931860).

  - s390/smp: only send external call ipi if needed
    (bsc#929879).

  - s390/spinlock,rwlock: always to a load-and-test first
    (bsc#929879).

  - s390/spinlock: cleanup spinlock code (bsc#929879).

  - s390/spinlock: optimize spin_unlock code (bsc#929879).

  - s390/spinlock: optimize spinlock code sequence
    (bsc#929879).

  - s390/spinlock: refactor arch_spin_lock_wait[_flags]
    (bsc#929879).

  - s390/time: use stck clock fast for do_account_vtime
    (bsc#929879).

  - s390: Remove zfcpdump NR_CPUS dependency (bsc#929879).

  - s390: add z13 code generation support (bsc#929879).

  - s390: avoid z13 cache aliasing (bsc#929879).

  - s390: fix control register update (bsc#929879).

  - s390: optimize control register update (bsc#929879).

  - s390: z13 base performance (bsc#929879).

  - sched: fix __sched_setscheduler() vs load balancing race
    (bsc#921430)

  - scsi: retry MODE SENSE on unit attention (bsc#895814).

  - scsi_dh_alua: Recheck state on unit attention
    (bsc#895814).

  - scsi_dh_alua: fixup crash in alua_rtpg_work()
    (bsc#895814).

  - scsi_dh_alua: parse device id instead of target id
    (bsc#895814).

  - scsi_dh_alua: recheck RTPG in regular intervals
    (bsc#895814).

  - scsi_dh_alua: update all port states (bsc#895814).

  - sd: always retry READ CAPACITY for ALUA state transition
    (bsc#895814).

  - st: NULL pointer dereference panic caused by use after
    kref_put by st_open (bsc#936875).

  - supported.conf: add btrfs to kernel-$flavor-base
    (bsc#933637)

  - udf: Remove repeated loads blocksize (bsc#933907).

  - usb: core: Fix USB 3.0 devices lost in NOTATTACHED state
    after a hub port reset (bsc#938024).

  - vTPM: set virtual device before passing to
    ibmvtpm_reset_crq (bsc#937087).

  - vfs: add super_operations->get_inode_dev (bsc#927455).

  - virtio-ccw: virtio-ccw adapter interrupt support
    (bsc#931860).

  - virtio-rng: do not crash if virtqueue is broken
    (bsc#931860).

  - virtio: fail adding buffer on broken queues
    (bsc#931860).

  - virtio: virtio_break_device() to mark all virtqueues
    broken (bsc#931860).

  - virtio_blk: verify if queue is broken after
    virtqueue_get_buf() (bsc#931860).

  - virtio_ccw: fix hang in set offline processing
    (bsc#931860).

  - virtio_ccw: fix vcdev pointer handling issues
    (bsc#931860).

  - virtio_ccw: introduce device_lost in virtio_ccw_device
    (bsc#931860).

  - virtio_net: do not crash if virtqueue is broken
    (bsc#931860).

  - virtio_net: verify if queue is broken after
    virtqueue_get_buf() (bsc#931860).

  - virtio_ring: adapt to notify() returning bool
    (bsc#931860).

  - virtio_ring: add new function virtqueue_is_broken()
    (bsc#931860).

  - virtio_ring: change host notification API (bsc#931860).

  - virtio_ring: let virtqueue_{kick()/notify()} return a
    bool (bsc#931860).

  - virtio_ring: plug kmemleak false positive (bsc#931860).

  - virtio_scsi: do not call virtqueue_add_sgs(... GFP_NOIO)
    holding spinlock (bsc#931860).

  - virtio_scsi: verify if queue is broken after
    virtqueue_get_buf() (bsc#931860).

  - vmxnet3: Bump up driver version number (bsc#936423).

  - vmxnet3: Changes for vmxnet3 adapter version 2 (fwd)
    (bug#936423).

  - vmxnet3: Fix memory leaks in rx path (fwd) (bug#936423).

  - vmxnet3: Register shutdown handler for device (fwd)
    (bug#936423).

  - x86/PCI: Use host bridge _CRS info on Foxconn
    K8M890-8237A (bsc#907092).

  - x86/PCI: Use host bridge _CRS info on systems with >32
    bit addressing (bsc#907092).

  - x86/kgr: move kgr infrastructure from asm to C.

  - x86/mm: Improve AMD Bulldozer ASLR workaround
    (bsc#937032).

  - xfrm: release dst_orig in case of error in xfrm_lookup()
    (bsc#932793).

  - xfs: Skip dirty pages in ->releasepage (bsc#915183).

  - xfs: fix xfs_setattr for DMAPI (bsc#932900).

  - xfs_dmapi: fix transaction ilocks (bsc#932899).

  - xfs_dmapi: fix value from newer Linux strnlen_user()
    (bsc#932897).

  - xfs_dmapi: xfs_dm_rdwr() uses dir file ops not file's
    ops (bsc#932898).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/854817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/854824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/858727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/866911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/867362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/895814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/903279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/907092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/908491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9728.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9729.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9730.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9731.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3212.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4167.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4692.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5364.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5366.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151324-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1dcc37f6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2015-356=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-356=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-356=1

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2015-356=1

SUSE Linux Enterprise Live Patching 12 :

zypper in -t patch SUSE-SLE-Live-Patching-12-2015-356=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-356=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"kernel-default-man-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-debuginfo-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debuginfo-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debugsource-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-devel-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-syms-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-devel-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-syms-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.44-52.10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.44-52.10.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUSE Linux Enterprise 12 kernel");
}
