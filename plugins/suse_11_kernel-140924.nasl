#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(78650);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2013-1979", "CVE-2014-1739", "CVE-2014-2706", "CVE-2014-3153", "CVE-2014-4027", "CVE-2014-4171", "CVE-2014-4508", "CVE-2014-4667", "CVE-2014-4943", "CVE-2014-5077", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-6410");

  script_name(english:"SuSE 11.3 Security Update : Linux kernel (SAT Patch Numbers 9746 / 9749 / 9751)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 3 kernel has been updated to
fix various bugs and security issues.

The following security bugs have been fixed :

  - The media_device_enum_entities function in
    drivers/media/media-device.c in the Linux kernel before
    3.14.6 does not initialize a certain data structure,
    which allows local users to obtain sensitive information
    from kernel memory by leveraging /dev/media0 read access
    for a MEDIA_IOC_ENUM_ENTITIES ioctl call. (bnc#882804).
    (CVE-2014-1739)

  - mm/shmem.c in the Linux kernel through 3.15.1 does not
    properly implement the interaction between range
    notification and hole punching, which allows local users
    to cause a denial of service (i_mutex hold) by using the
    mmap system call to access a hole, as demonstrated by
    interfering with intended shmem activity by blocking
    completion of (1) an MADV_REMOVE madvise call or (2) an
    FALLOC_FL_PUNCH_HOLE fallocate call. (bnc#883518).
    (CVE-2014-4171)

  - arch/x86/kernel/entry_32.S in the Linux kernel through
    3.15.1 on 32-bit x86 platforms, when syscall auditing is
    enabled and the sep CPU feature flag is set, allows
    local users to cause a denial of service (OOPS and
    system crash) via an invalid syscall number, as
    demonstrated by number 1000. (bnc#883724).
    (CVE-2014-4508)

  - The sctp_association_free function in
    net/sctp/associola.c in the Linux kernel before 3.15.2
    does not properly manage a certain backlog value, which
    allows remote attackers to cause a denial of service
    (socket outage) via a crafted SCTP packet. (bnc#885422).
    (CVE-2014-4667)

  - The PPPoL2TP feature in net/l2tp/l2tp_ppp.c in the Linux
    kernel through 3.15.6 allows local users to gain
    privileges by leveraging data-structure differences
    between an l2tp socket and an inet socket. (bnc#887082).
    (CVE-2014-4943)

  - The sctp_assoc_update function in net/sctp/associola.c
    in the Linux kernel through 3.15.8, when SCTP
    authentication is enabled, allows remote attackers to
    cause a denial of service (NULL pointer dereference and
    OOPS) by starting to establish an association between
    two endpoints immediately after an exchange of INIT and
    INIT ACK chunks to establish an earlier association
    between these endpoints in the opposite direction.
    (bnc#889173). (CVE-2014-5077)

  - Stack consumption vulnerability in the
    parse_rock_ridge_inode_internal function in
    fs/isofs/rock.c in the Linux kernel through 3.16.1
    allows local users to cause a denial of service
    (uncontrolled recursion, and system crash or reboot) via
    a crafted iso9660 image with a CL entry referring to a
    directory entry that has a CL entry. (bnc#892490).
    (CVE-2014-5471)

  - The parse_rock_ridge_inode_internal function in
    fs/isofs/rock.c in the Linux kernel through 3.16.1
    allows local users to cause a denial of service
    (unkillable mount process) via a crafted iso9660 image
    with a self-referential CL entry. (bnc#892490).
    (CVE-2014-5472)

  - Race condition in the mac80211 subsystem in the Linux
    kernel before 3.13.7 allows remote attackers to cause a
    denial of service (system crash) via network traffic
    that improperly interacts with the WLAN_STA_PS_STA state
    (aka power-save mode), related to sta_info.c and tx.c.
    (bnc#871797). (CVE-2014-2706)

  - The rd_build_device_space function in
    drivers/target/target_core_rd.c in the Linux kernel
    before 3.14 does not properly initialize a certain data
    structure, which allows local users to obtain sensitive
    information from ramdisk_mcp memory by leveraging access
    to a SCSI initiator. (bnc#882639). (CVE-2014-4027)

  - The futex_requeue function in kernel/futex.c in the
    Linux kernel through 3.14.5 does not ensure that calls
    have two different futex addresses, which allows local
    users to gain privileges via a crafted FUTEX_REQUEUE
    command that facilitates unsafe waiter modification.
    (bnc#880892). (CVE-2014-3153)

  - Avoid infinite loop when processing indirect ICBs
    (bnc#896689) The following non-security bugs have been
    fixed:. (CVE-2014-6410)

  - ACPI / PAD: call schedule() when need_resched() is true.
    (bnc#866911)

  - ACPI: Fix bug when ACPI reset register is implemented in
    system memory. (bnc#882900)

  - ACPI: Limit access to custom_method. (bnc#884333)

  - ALSA: hda - Enabling Realtek ALC 671 codec. (bnc#891746)

  - Add option to automatically enforce module signatures
    when in Secure Boot mode. (bnc#884333)

  - Add secure_modules() call. (bnc#884333)

  - Add wait_on_atomic_t() and wake_up_atomic_t().
    (bnc#880344)

  - Backported new patches of Lock down functions for UEFI
    secure boot Also updated series.conf and removed old
    patches.

  - Btrfs: Return EXDEV for cross file system snapshot.

  - Btrfs: abort the transaction when we does not find our
    extent ref.

  - Btrfs: avoid warning bomb of btrfs_invalidate_inodes.

  - Btrfs: cancel scrub on transaction abortion.

  - Btrfs: correctly set profile flags on seqlock retry.

  - Btrfs: does not check nodes for extent items.

  - Btrfs: fix a possible deadlock between scrub and
    transaction committing.

  - Btrfs: fix corruption after write/fsync failure + fsync
    + log recovery. (bnc#894200)

  - Btrfs: fix csum tree corruption, duplicate and outdated
    checksums. (bnc#891619)

  - Btrfs: fix double free in find_lock_delalloc_range.

  - Btrfs: fix possible memory leak in btrfs_create_tree().

  - Btrfs: fix use of uninit 'ret' in
    end_extent_writepage().

  - Btrfs: free delayed node outside of root->inode_lock.
    (bnc#866864)

  - Btrfs: make DEV_INFO ioctl available to anyone.

  - Btrfs: make FS_INFO ioctl available to anyone.

  - Btrfs: make device scan less noisy.

  - Btrfs: make sure there are not any read requests before
    stopping workers.

  - Btrfs: more efficient io tree navigation on
    wait_extent_bit.

  - Btrfs: output warning instead of error when loading free
    space cache failed.

  - Btrfs: retrieve more info from FS_INFO ioctl.

  - Btrfs: return EPERM when deleting a default subvolume.
    (bnc#869934)

  - Btrfs: unset DCACHE_DISCONNECTED when mounting default
    subvol. (bnc#866615)

  - Btrfs: use right type to get real comparison.

  - Btrfs: wake up @scrub_pause_wait as much as we can.

  - Btrfs: wake up transaction thread upon remount.

  - CacheFiles: Add missing retrieval completions.
    (bnc#880344)

  - CacheFiles: Does not try to dump the index key if the
    cookie has been cleared. (bnc#880344)

  - CacheFiles: Downgrade the requirements passed to the
    allocator. (bnc#880344)

  - CacheFiles: Fix the marking of cached pages.
    (bnc#880344)

  - CacheFiles: Implement invalidation. (bnc#880344)

  - CacheFiles: Make some debugging statements conditional.
    (bnc#880344)

  - Drivers: hv: util: Fix a bug in the KVP code.
    (bnc#886840)

  - Drivers: hv: vmbus: Fix a bug in the channel callback
    dispatch code. (bnc#886840)

  - FS-Cache: Add transition to handle invalidate
    immediately after lookup. (bnc#880344)

  - FS-Cache: Check that there are no read ops when cookie
    relinquished. (bnc#880344)

  - FS-Cache: Clear remaining page count on retrieval
    cancellation. (bnc#880344)

  - FS-Cache: Convert the object event ID #defines into an
    enum. (bnc#880344)

  - FS-Cache: Does not sleep in page release if __GFP_FS is
    not set. (bnc#880344)

  - FS-Cache: Does not use spin_is_locked() in assertions.
    (bnc#880344)

  - FS-Cache: Exclusive op submission can BUG if there is
    been an I/O error. (bnc#880344)

  - FS-Cache: Fix __wait_on_atomic_t() to call the action
    func if the counter != 0. (bnc#880344)

  - FS-Cache: Fix object state machine to have separate work
    and wait states. (bnc#880344)

  - FS-Cache: Fix operation state management and accounting.
    (bnc#880344)

  - FS-Cache: Fix signal handling during waits. (bnc#880344)

  - FS-Cache: Initialise the object event mask with the
    calculated mask. (bnc#880344)

  - FS-Cache: Limit the number of I/O error reports for a
    cache. (bnc#880344)

  - FS-Cache: Make cookie relinquishment wait for
    outstanding reads. (bnc#880344)

  - FS-Cache: Mark cancellation of in-progress operation.
    (bnc#880344)

  - FS-Cache: One of the write operation paths doeses not
    set the object state. (bnc#880344)

  - FS-Cache: Provide proper invalidation. (bnc#880344)

  - FS-Cache: Simplify cookie retention for fscache_objects,
    fixing oops. (bnc#880344)

  - FS-Cache: The retrieval remaining-pages counter needs to
    be atomic_t. (bnc#880344)

  - FS-Cache: Uninline fscache_object_init(). (bnc#880344)

  - FS-Cache: Wrap checks on object state. (bnc#880344)

  - HID: usbhid: add always-poll quirk. (bnc#888607)

  - HID: usbhid: enable always-poll quirk for Elan
    Touchscreen. (bnc#888607)

  - IB/iser: Add TIMEWAIT_EXIT event handling. (bnc#890297)

  - Ignore 'flags' change to event_constraint. (bnc#876114)

  - Ignore data_src/weight changes to perf_sample_data.
    (bnc#876114)

  - NFS: Allow more operations in an NFSv4.1 request.
    (bnc#890513)

  - NFS: Clean up helper function nfs4_select_rw_stateid().
    (bnc#888968)

  - NFS: Does not copy read delegation stateids in setattr.
    (bnc#888968)

  - NFS: Does not use a delegation to open a file when
    returning that delegation. (bnc#888968, bnc#892200,
    bnc#893596, bnc#893496)

  - NFS: Fixes for NFS RCU-walk support in line with code
    going upstream

  - NFS: Use FS-Cache invalidation. (bnc#880344)

  - NFS: allow lockless access to access_cache. (bnc#866130)

  - NFS: avoid mountpoint being displayed as ' (deleted)' in
    /proc/mounts. (bnc#888591)

  - NFS: nfs4_do_open should add negative results to the
    dcache. (bnc#866130)

  - NFS: nfs_migrate_page() does not wait for FS-Cache to
    finish with a page. (bnc#880344)

  - NFS: nfs_open_revalidate: only evaluate parent if it
    will be used. (bnc#866130)

  - NFS: prepare for RCU-walk support but pushing tests
    later in code. (bnc#866130)

  - NFS: support RCU_WALK in nfs_permission(). (bnc#866130)

  - NFS: teach nfs_lookup_verify_inode to handle LOOKUP_RCU.
    (bnc#866130)

  - NFS: teach nfs_neg_need_reval to understand LOOKUP_RCU.
    (bnc#866130)

  - NFSD: Does not hand out delegations for 30 seconds after
    recalling them. (bnc#880370)

  - NFSv4 set open access operation call flag in
    nfs4_init_opendata_res. (bnc#888968, bnc#892200,
    bnc#893596, bnc#893496)

  - NFSv4: Add a helper for encoding opaque data.
    (bnc#888968)

  - NFSv4: Add a helper for encoding stateids. (bnc#888968)

  - NFSv4: Add helpers for basic copying of stateids.
    (bnc#888968)

  - NFSv4: Clean up nfs4_select_rw_stateid(). (bnc#888968)

  - NFSv4: Fix the return value of nfs4_select_rw_stateid.
    (bnc#888968)

  - NFSv4: Rename nfs4_copy_stateid(). (bnc#888968)

  - NFSv4: Resend the READ/WRITE RPC call if a stateid
    change causes an error. (bnc#888968)

  - NFSv4: Simplify the struct nfs4_stateid. (bnc#888968)

  - NFSv4: The stateid must remain the same for replayed RPC
    calls. (bnc#888968)

  - NFSv4: nfs4_stateid_is_current should return 'true' for
    an invalid stateid. (bnc#888968)

  - One more fix for kABI breakage.

  - PCI: Lock down BAR access when module security is
    enabled. (bnc#884333)

  - PCI: enable MPS 'performance' setting to properly handle
    bridge MPS. (bnc#883376)

  - PM / Hibernate: Add memory_rtree_find_bit function.
    (bnc#860441)

  - PM / Hibernate: Create a Radix-Tree to store memory
    bitmap. (bnc#860441)

  - PM / Hibernate: Implement position keeping in radix
    tree. (bnc#860441)

  - PM / Hibernate: Iterate over set bits instead of PFNs in
    swsusp_free(). (bnc#860441)

  - PM / Hibernate: Remove the old memory-bitmap
    implementation. (bnc#860441)

  - PM / Hibernate: Touch Soft Lockup Watchdog in
    rtree_next_node. (bnc#860441)

  - Restrict /dev/mem and /dev/kmem when module loading is
    restricted. (bnc#884333)

  - Reuse existing 'state' field to indicate
    PERF_X86_EVENT_PEBS_LDLAT. (bnc#876114)

  - USB: handle LPM errors during device suspend correctly.
    (bnc#849123)

  - Update kabi files to reflect fscache change.
    (bnc#880344)

  - Update x86_64 config files: re-enable SENSORS_W83627EHF.
    (bnc#891281)

  - VFS: Make more complete truncate operation available to
    CacheFiles. (bnc#880344)

  - [FEAT NET1222] ib_uverbs: Allow explicit mmio trigger
    (FATE#83366, ltc#83367).

  - acpi: Ignore acpi_rsdp kernel parameter when module
    loading is restricted. (bnc#884333)

  - af_iucv: correct cleanup if listen backlog is full
    (bnc#885262, LTC#111728).

  - asus-wmi: Restrict debugfs interface when module loading
    is restricted. (bnc#884333)

  - autofs4: allow RCU-walk to walk through autofs4.
    (bnc#866130)

  - autofs4: avoid taking fs_lock during rcu-walk.
    (bnc#866130)

  - autofs4: does not take spinlock when not needed in
    autofs4_lookup_expiring. (bnc#866130)

  - autofs4: factor should_expire() out of
    autofs4_expire_indirect. (bnc#866130)

  - autofs4: make 'autofs4_can_expire' idempotent.
    (bnc#866130)

  - autofs4: remove a redundant assignment. (bnc#866130)

  - autofs: fix lockref lookup. (bnc#888591)

  - be2net: add dma_mapping_error() check for
    dma_map_page(). (bnc#881759)

  - block: add cond_resched() to potentially long running
    ioctl discard loop. (bnc#884725)

  - block: fix race between request completion and timeout
    handling. (bnc#881051)

  - cdc-ether: clean packet filter upon probe. (bnc#876017)

  - cpuset: Fix memory allocator deadlock. (bnc#876590)

  - crypto: Allow CRYPTO_FIPS without MODULE_SIGNATURES. Not
    all archs have them, but some are FIPS certified, with
    some kernel support.

  - crypto: fips - only panic on bad/missing crypto mod
    signatures. (bnc#887503)

  - crypto: testmgr - allow aesni-intel and
    ghash_clmulni-intel in fips mode. (bnc#889451)

  - dasd: validate request size before building CCW/TCW
    (bnc#891087, LTC#114068).

  - dm mpath: fix race condition between multipath_dtr and
    pg_init_done. (bnc#826486)

  - dm-mpath: fix panic on deleting sg device. (bnc#870161)

  - drm/ast: AST2000 cannot be detected correctly.
    (bnc#895983)

  - drm/ast: Actually load DP501 firmware when required.
    (bnc#895608 / bnc#871134)

  - drm/ast: Add missing entry to dclk_table[].

  - drm/ast: Add reduced non reduced mode parsing for wide
    screen mode. (bnc#892723)

  - drm/ast: initial DP501 support (v0.2). (bnc#871134)

  - drm/ast: open key before detect chips. (bnc#895983)

  - drm/i915: Fix up cpt pixel multiplier enable sequence.
    (bnc#879304)

  - drm/i915: Only apply DPMS to the encoder if enabled.
    (bnc#893064)

  - drm/i915: clear the FPGA_DBG_RM_NOCLAIM bit at driver
    init. (bnc#869055)

  - drm/i915: create functions for the 'unclaimed register'
    checks. (bnc#869055)

  - drm/i915: use FPGA_DBG for the 'unclaimed register'
    checks. (bnc#869055)

  - drm/mgag200: Initialize data needed to map fbdev memory.
    (bnc#806990)

  - e1000e: enable support for new device IDs. (bnc#885509)

  - fs/fscache: remove spin_lock() from the condition in
    while(). (bnc#880344)

  - hibernate: Disable in a signed modules environment.
    (bnc#884333)

  - hugetlb: does not use ERR_PTR with VM_FAULT* values

  - ibmvscsi: Abort init sequence during error recovery.
    (bnc#885382)

  - ibmvscsi: Add memory barriers for send / receive.
    (bnc#885382)

  - inet: add a redirect generation id in inetpeer.
    (bnc#860593)

  - inetpeer: initialize ->redirect_genid in inet_getpeer().
    (bnc#860593)

  - ipv6: tcp: fix tcp_v6_conn_request(). (bnc#887645)

  - kabi: hide bnc#860593 changes of struct
    inetpeer_addr_base. (bnc#860593)

  - kernel: 3215 tty hang (bnc#891087, LTC#114562).

  - kernel: fix data corruption when reading /proc/sysinfo
    (bnc#891087, LTC#114480).

  - kernel: fix kernel oops with load of fpc register
    (bnc#889061, LTC#113596).

  - kernel: sclp console tty reference counting (bnc#891087,
    LTC#115466).

  - kexec: Disable at runtime if the kernel enforces module
    loading restrictions. (bnc#884333)

  - md/raid6: avoid data corruption during recovery of
    double-degraded RAID6.

  - memcg, vmscan: Fix forced scan of anonymous pages
    (memory reclaim fix).

  - memcg: do not expose uninitialized mem_cgroup_per_node
    to world. (bnc#883096)

  - mm, hugetlb: add VM_NORESERVE check in
    vma_has_reserves()

  - mm, hugetlb: change variable name reservations to resv

  - mm, hugetlb: decrement reserve count if VM_NORESERVE
    alloc page cache

  - mm, hugetlb: defer freeing pages when gathering surplus
    pages

  - mm, hugetlb: do not use a page in page cache for cow
    optimization

  - mm, hugetlb: fix and clean-up node iteration code to
    alloc or free

  - mm, hugetlb: fix race in region tracking

  - mm, hugetlb: fix subpool accounting handling

  - mm, hugetlb: improve page-fault scalability

  - mm, hugetlb: improve, cleanup resv_map parameters

  - mm, hugetlb: move up the code which check availability
    of free huge page

  - mm, hugetlb: protect reserved pages when soft offlining
    a hugepage

  - mm, hugetlb: remove decrement_hugepage_resv_vma()

  - mm, hugetlb: remove redundant list_empty check in
    gather_surplus_pages()

  - mm, hugetlb: remove resv_map_put

  - mm, hugetlb: remove useless check about mapping type

  - mm, hugetlb: return a reserved page to a reserved pool
    if failed

  - mm, hugetlb: trivial commenting fix

  - mm, hugetlb: unify region structure handling

  - mm, hugetlb: unify region structure handling kabi

  - mm, hugetlb: use long vars instead of int in
    region_count() (Hugetlb Fault Scalability).

  - mm, hugetlb: use vma_resv_map() map types

  - mm, oom: fix badness score underflow. (bnc#884582,
    bnc#884767)

  - mm, oom: normalize oom scores to oom_score_adj scale
    only for userspace. (bnc#884582, bnc#884767)

  - mm, thp: do not allow thp faults to avoid cpuset
    restrictions. (bnc#888849)

  - net/mlx4_core: Load higher level modules according to
    ports type. (bnc#887680)

  - net/mlx4_core: Load the IB driver when the device
    supports IBoE. (bnc#887680)

  - net/mlx4_en: Fix a race between napi poll function and
    RX ring cleanup. (bnc#863586)

  - net/mlx4_en: Fix selftest failing on non 10G link speed.
    (bnc#888058)

  - net: fix checksumming features handling in output path.
    (bnc#891259)

  - pagecache_limit: batch large nr_to_scan targets.
    (bnc#895221)

  - pagecachelimit: reduce lru_lock congestion for heavy
    parallel reclaim fix. (bnc#895680)

  - perf/core: Add weighted samples. (bnc#876114)

  - perf/x86: Add flags to event constraints. (bnc#876114)

  - perf/x86: Add memory profiling via PEBS Load Latency.
    (bnc#876114)

  - perf: Add generic memory sampling interface.
    (bnc#876114)

  - qla2xxx: Avoid escalating the SCSI error handler if the
    command is not found in firmware. (bnc#859840)

  - qla2xxx: Clear loop_id for ports that are marked lost
    during fabric scanning. (bnc#859840)

  - qla2xxx: Does not check for firmware hung during the
    reset context for ISP82XX. (bnc#859840)

  - qla2xxx: Issue abort command for outstanding commands
    during cleanup when only firmware is alive. (bnc#859840)

  - qla2xxx: Reduce the time we wait for a command to
    complete during SCSI error handling. (bnc#859840)

  - qla2xxx: Set host can_queue value based on available
    resources. (bnc#859840)

  - restore smp_mb() in unlock_new_inode(). (bnc#890526)

  - s390/pci: introduce lazy IOTLB flushing for DMA unmap
    (bnc#889061, LTC#113725).

  - sched: fix the theoretical signal_wake_up() vs
    schedule() race. (bnc#876055)

  - sclp_vt220: Enable integrated ASCII console per default
    (bnc#885262, LTC#112035).

  - scsi_dh: use missing accessor 'scsi_device_from_queue'.
    (bnc#889614)

  - scsi_transport_fc: Cap dev_loss_tmo by fast_io_fail.
    (bnc#887608)

  - scsiback: correct grant page unmapping.

  - scsiback: fix retry handling in __report_luns().

  - scsiback: free resources after error.

  - sunrpc/auth: allow lockless (rcu) lookup of credential
    cache. (bnc#866130)

  - supported.conf: remove external from drivers/net/veth.
    (bnc#889727)

  - supported.conf: support net/sched/act_police.ko.
    (bnc#890426)

  - tcp: adapt selected parts of RFC 5682 and PRR logic.
    (bnc#879921)

  - tg3: Change nvram command timeout value to 50ms.
    (bnc#855657)

  - tg3: Override clock, link aware and link idle mode
    during NVRAM dump. (bnc#855657)

  - tg3: Set the MAC clock to the fastest speed during boot
    code load. (bnc#855657)

  - usb: Does not enable LPM if the exit latency is zero.
    (bnc#832309)

  - usbcore: Does not log on consecutive debounce failures
    of the same port. (bnc#888105)

  - usbhid: fix PIXART optical mouse. (bnc#888607)

  - uswsusp: Disable when module loading is restricted.
    (bnc#884333)

  - vscsi: support larger transfer sizes. (bnc#774818)

  - writeback: Do not sync data dirtied after sync start.
    (bnc#833820)

  - x86 thermal: Delete power-limit-notification console
    messages. (bnc#882317)

  - x86 thermal: Disable power limit notification interrupt
    by default. (bnc#882317)

  - x86 thermal: Re-enable power limit notification
    interrupt by default. (bnc#882317)

  - x86, cpu hotplug: Fix stack frame warning in
    check_irq_vectors_for_cpu_disable(). (bnc#887418)

  - x86/UV: Add call to KGDB/KDB from NMI handler.
    (bnc#888847)

  - x86/UV: Add kdump to UV NMI handler. (bnc#888847)

  - x86/UV: Add summary of cpu activity to UV NMI handler.
    (bnc#888847)

  - x86/UV: Move NMI support. (bnc#888847)

  - x86/UV: Update UV support for external NMI signals.
    (bnc#888847)

  - x86/uv/nmi: Fix Sparse warnings. (bnc#888847)

  - x86: Add check for number of available vectors before
    CPU down. (bnc#887418)

  - x86: Lock down IO port access when module security is
    enabled. (bnc#884333)

  - x86: Restrict MSR access when module loading is
    restricted. (bnc#884333)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=826486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=832309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=855657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=859840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=866130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=866615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=866864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=866911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=869055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=869934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=870161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=876017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=876055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=876114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=876590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=879304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=879921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=880344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=880370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=880892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=881051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=881759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=882317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=882639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=882804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=882900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=883096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=883376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=883518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=883724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=884333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=884582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=884725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=884767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=885262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=885382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=885422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=885509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=886840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=888058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=888105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=888591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=888607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=888847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=888849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=888968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=889061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=889173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=889451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=889614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=889727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=890297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=890426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=890513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=890526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=891087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=891259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=891281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=891619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=891746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=892200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=892490"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=892723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=893064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=893496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=893596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=894200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=895221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=895608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=895680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=895983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=896689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1979.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1739.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2706.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3153.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4027.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4171.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4508.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4667.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4943.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-5077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-5471.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-5472.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6410.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 9746 / 9749 / 9751 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android \'Towelroot\' Futex Requeue Kernel Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-base-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-devel-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-extra-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-base-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-extra-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-source-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-syms-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-trace-devel-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-base-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-extra-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-kmp-default-4.2.4_04_3.0.101_0.40-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-kmp-pae-4.2.4_04_3.0.101_0.40-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-base-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-devel-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-extra-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-source-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-syms-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.4_04_3.0.101_0.40-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-base-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-devel-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-source-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-syms-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-base-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-devel-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-base-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-base-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-kmp-default-4.2.4_04_3.0.101_0.40-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-kmp-pae-4.2.4_04_3.0.101_0.40-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"kernel-default-man-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.40.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.4_04_3.0.101_0.40-0.7.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
