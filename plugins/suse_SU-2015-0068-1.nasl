#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0068-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83665);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2013-6405", "CVE-2014-3185", "CVE-2014-3610", "CVE-2014-3611", "CVE-2014-3647", "CVE-2014-3673", "CVE-2014-7826", "CVE-2014-7841", "CVE-2014-8133", "CVE-2014-9090", "CVE-2014-9322");
  script_bugtraq_id(63999, 69781, 70742, 70743, 70748, 70883, 70971, 71081, 71250, 71684, 71685);
  script_osvdb_id(100422, 110732, 113727, 113823, 113899, 114370, 114575, 115163, 115919, 115920);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2015:0068-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 kernel was updated to 3.12.31 to receive
various security and bugfixes.

Security issues fixed: CVE-2014-9322: A local privilege escalation in
the x86_64 32bit compatibility signal handling was fixed, which could
be used by local attackers to crash the machine or execute code.

  - CVE-2014-9090: Various issues in LDT handling in 32bit
    compatibility mode on the x86_64 platform were fixed,
    where local attackers could crash the machine.

  - CVE-2014-8133: Insufficient validation of TLS register
    usage could leak information from the kernel stack to
    userspace.

  - CVE-2014-7826: kernel/trace/trace_syscalls.c in the
    Linux kernel did not properly handle private syscall
    numbers during use of the ftrace subsystem, which
    allowed local users to gain privileges or cause a denial
    of service (invalid pointer dereference) via a crafted
    application.

  - CVE-2014-3647: Nadav Amit reported that the KVM (Kernel
    Virtual Machine) mishandled noncanonical addresses when
    emulating instructions that change the rip (Instruction
    Pointer). A guest user with access to I/O or the MMIO
    could use this flaw to cause a denial of service (system
    crash) of the guest.

  - CVE-2014-3611: A race condition flaw was found in the
    way the Linux kernel's KVM subsystem handled PIT
    (Programmable Interval Timer) emulation. A guest user
    who has access to the PIT I/O ports could use this flaw
    to crash the host.

  - CVE-2014-3610: If the guest writes a noncanonical value
    to certain MSR registers, KVM will write that value to
    the MSR in the host context and a #GP will be raised
    leading to kernel panic. A privileged guest user could
    have used this flaw to crash the host.

  - CVE-2014-7841: A remote attacker could have used a flaw
    in SCTP to crash the system by sending a maliciously
    prepared SCTP packet in order to trigger a NULL pointer
    dereference on the server.

  - CVE-2014-3673: The SCTP implementation in the Linux
    kernel allowed remote attackers to cause a denial of
    service (system crash) via a malformed ASCONF chunk,
    related to net/sctp/sm_make_chunk.c and
    net/sctp/sm_statefuns.c.

  - CVE-2014-3185: Multiple buffer overflows in the
    command_port_read_callback function in
    drivers/usb/serial/whiteheat.c in the Whiteheat USB
    Serial Driver in the Linux kernel allowed physically
    proximate attackers to execute arbitrary code or cause a
    denial of service (memory corruption and system crash)
    via a crafted device that provides a large amount of (1)
    EHCI or (2) XHCI data associated with a bulk response.

Bugs fixed: BTRFS :

  - btrfs: fix race that makes btrfs_lookup_extent_info miss
    skinny extent items (bnc#904077).

  - btrfs: fix invalid leaf slot access in
    btrfs_lookup_extent() (bnc#904077).

  - btrfs: avoid returning -ENOMEM in convert_extent_bit()
    too early (bnc#902016).

  - btrfs: make find_first_extent_bit be able to cache any
    state (bnc#902016).

  - btrfs: deal with convert_extent_bit errors to avoid fs
    corruption (bnc#902016).

  - btrfs: be aware of btree inode write errors to avoid fs
    corruption (bnc#899551).

  - btrfs: add missing end_page_writeback on
    submit_extent_page failure (bnc#899551).

  - btrfs: fix crash of btrfs_release_extent_buffer_page
    (bnc#899551).

  - btrfs: ensure readers see new data after a clone
    operation (bnc#898234).

  - btrfs: avoid visiting all extent items when cloning a
    range (bnc#898234).

  - btrfs: fix clone to deal with holes when NO_HOLES
    feature is enabled (bnc#898234).

  - btrfs: make fsync work after cloning into a file
    (bnc#898234).

  - btrfs: fix use-after-free when cloning a trailing file
    hole (bnc#898234).

  - btrfs: clone, don't create invalid hole extent map
    (bnc#898234).

  - btrfs: limit the path size in send to PATH_MAX
    (bnc#897770).

  - btrfs: send, fix more issues related to directory
    renames (bnc#897770).

  - btrfs: send, remove dead code from
    __get_cur_name_and_parent (bnc#897770).

  - btrfs: send, account for orphan directories when
    building path strings (bnc#897770).

  - btrfs: send, avoid unnecessary inode item lookup in the
    btree (bnc#897770).

  - btrfs: send, fix incorrect ref access when using extrefs
    (bnc#897770).

  - btrfs: send, build path string only once in send_hole
    (bnc#897770).

  - btrfs: part 2, fix incremental send's decision to delay
    a dir move/rename (bnc#897770).

  - btrfs: fix incremental send's decision to delay a dir
    move/rename (bnc#897770).

  - btrfs: remove unnecessary inode generation lookup in
    send (bnc#897770).

  - btrfs: avoid unnecessary utimes update in incremental
    send (bnc#897770).

  - btrfs: fix send issuing outdated paths for utimes, chown
    and chmod (bnc#897770).

  - btrfs: fix send attempting to rmdir non-empty
    directories (bnc#897770).

  - btrfs: send, don't send rmdir for same target multiple
    times (bnc#897770).

  - btrfs: incremental send, fix invalid path after dir
    rename (bnc#897770).

  - btrfs: fix assert screwup for the pending move stuff
    (bnc#897770).

  - btrfs: make some tree searches in send.c more efficient
    (bnc#897770).

  - btrfs: use right extent item position in send when
    finding extent clones (bnc#897770).

  - btrfs: more send support for parent/child dir
    relationship inversion (bnc#897770).

  - btrfs: fix send dealing with file renames and directory
    moves (bnc#897770).

  - btrfs: add missing error check in incremental send
    (bnc#897770).

  - btrfs: make send's file extent item search more
    efficient (bnc#897770).

  - btrfs: fix infinite path build loops in incremental send
    (bnc#897770).

  - btrfs: send, don't delay dir move if there's a new
    parent inode (bnc#897770).

  - btrfs: add helper btrfs_fdatawrite_range (bnc#902010).

  - btrfs: correctly flush compressed data before/after
    direct IO (bnc#902010).

  - btrfs: make inode.c:compress_file_range() return void
    (bnc#902010).

  - btrfs: report error after failure inlining extent in
    compressed write path (bnc#902010).

  - btrfs: don't ignore compressed bio write errors
    (bnc#902010).

  - btrfs: make inode.c:submit_compressed_extents() return
    void (bnc#902010).

  - btrfs: process all async extents on compressed write
    failure (bnc#902010).

  - btrfs: don't leak pages and memory on compressed write
    error (bnc#902010).

  - btrfs: fix hang on compressed write error (bnc#902010).

  - btrfs: set page and mapping error on compressed write
    failure (bnc#902010).

  - btrfs: fix kfree on list_head in
    btrfs_lookup_csums_range error cleanup (bnc#904115).

Hyper-V :

  - hyperv: Fix a bug in netvsc_send().

  - hyperv: Fix a bug in netvsc_start_xmit().

  - drivers: hv: vmbus: Enable interrupt driven flow
    control.

  - drivers: hv: vmbus: Properly protect calls to
    smp_processor_id().

  - drivers: hv: vmbus: Cleanup hv_post_message().

  - drivers: hv: vmbus: Cleanup vmbus_close_internal().

  - drivers: hv: vmbus: Fix a bug in vmbus_open().

  - drivers: hv: vmbus: Cleanup vmbus_establish_gpadl().

  - drivers: hv: vmbus: Cleanup vmbus_teardown_gpadl().

  - drivers: hv: vmbus: Cleanup vmbus_post_msg().

  - storvsc: get rid of overly verbose warning messages.

  - hyperv: NULL dereference on error.

  - hyperv: Increase the buffer length for
    netvsc_channel_cb().

zSeries / S390 :

  - s390: pass march flag to assembly files as well
    (bnc#903279, LTC#118177).

  - kernel: reduce function tracer overhead (bnc#903279,
    LTC#118177).

  - SUNRPC: Handle EPIPE in xprt_connect_status
    (bnc#901090).

  - SUNRPC: Ensure that we handle ENOBUFS errors correctly
    (bnc#901090).

  - SUNRPC: Ensure call_connect_status() deals correctly
    with SOFTCONN tasks (bnc#901090).

  - SUNRPC: Ensure that call_connect times out correctly
    (bnc#901090).

  - SUNRPC: Handle connect errors ECONNABORTED and
    EHOSTUNREACH (bnc#901090).

  - SUNRPC: Ensure xprt_connect_status handles all potential
    connection errors (bnc#901090).

  - SUNRPC: call_connect_status should recheck bind and
    connect status on error (bnc#901090).

kGraft :

  - kgr: force patching process to succeed (fate#313296).

  - kgr: usb-storage, mark kthread safe (fate#313296
    bnc#899908).

  - Refresh patches.suse/kgr-0039-kgr-fix-ugly-race.patch.
    Fix few bugs, and also races (immutable vs
    mark_processes vs other threads).

  - kgr: always use locked bit ops for thread_info->flags
    (fate#313296).

  - kgr: lower the workqueue scheduling timeout (fate#313296
    bnc#905087).

  - kgr: mark even more kthreads (fate#313296 bnc#904871).

  - rpm/kernel-binary.spec.in: Provide name-version-release
    for kgraft packages (bnc#901925)

Other :

  - NFSv4: test SECINFO RPC_AUTH_GSS pseudoflavors for
    support (bnc#905758).

  - Enable cmac(aes) and cmac(3des_ede) for FIPS mode
    (bnc#905296 bnc#905772).

  - scsi_dh_alua: disable ALUA handling for non-disk devices
    (bnc#876633).

  - powerpc/vphn: NUMA node code expects big-endian
    (bsc#900126).

  - net: fix checksum features handling in
    netif_skb_features() (bnc#891259).

  - be2net: Fix invocation of be_close() after be_clear()
    (bnc#895468).

  - PCI: pciehp: Clear Data Link Layer State Changed during
    init (bnc#898297).

  - PCI: pciehp: Use symbolic constants, not hard-coded
    bitmask (bnc#898297).

  - PCI: pciehp: Use link change notifications for hot-plug
    and removal (bnc#898297).

  - PCI: pciehp: Make check_link_active() non-static
    (bnc#898297).

  - PCI: pciehp: Enable link state change notifications
    (bnc#898297).

  - ALSA: hda - Treat zero connection as non-error
    (bnc#902898).

  - bcache: add mutex lock for bch_is_open (bnc#902893).

  - futex: Fix a race condition between REQUEUE_PI and task
    death (bcn #851603 (futex scalability series)).

  - Linux 3.12.31 (bnc#895983 bnc#897912).

  - futex: Ensure get_futex_key_refs() always implies a
    barrier (bcn #851603 (futex scalability series)).

  - usbback: don't access request fields in shared ring more
    than once.

  - Update Xen patches to 3.12.30.

  - locking/rwsem: Avoid double checking before try
    acquiring write lock (Locking scalability.).

  - zcrypt: toleration of new crypto adapter hardware
    (bnc#894057, LTC#117041).

  - zcrypt: support for extended number of ap domains
    (bnc#894057, LTC#117041).

  - kABI: protect linux/fs.h include in mm/internal.h.

  - Linux 3.12.30 (FATE#315482 bnc#862957 bnc#863526
    bnc#870498).

  - Update
    patches.fixes/xfs-mark-all-internal-workqueues-as-freeza
    ble.patch (bnc#899785).

  - xfs: mark all internal workqueues as freezable.

  - drm/i915: Move DP port disable to post_disable for pch
    platforms (bnc#899787).

  - pagecachelimit: reduce lru_lock congestion for heavy
    parallel reclaim fix (bnc#895680).

  - Linux 3.12.29 (bnc#879255 bnc#880892 bnc#887046
    bnc#887418 bnc#891619 bnc#892612 bnc#892650 bnc#897101).

  - iommu/vt-d: Work around broken RMRR firmware entries
    (bnc#892860).

  - iommu/vt-d: Store bus information in RMRR PCI device
    path (bnc#892860).

  - iommu/vt-d: Only remove domain when device is removed
    (bnc#883139).

  - driver core: Add BUS_NOTIFY_REMOVED_DEVICE event
    (bnc#883139).

  - Update config files: Re-enable CONFIG_FUNCTION_PROFILER
    (bnc#899489) Option FUNCTION_PROFILER was enabled in
    debug and trace kernels so far, but it was accidentally
    disabled before tracing features were merged into the
    default kernel and the trace flavor was discarded. So
    all kernels are missing the feature now. Re-enable it.

  - xfs: xlog_cil_force_lsn doesn't always wait correctly.

  - scsi: clear 'host_scribble' upon successful abort
    (bnc#894863).

  - module: warn if module init + probe takes long
    (bnc#889297 bnc#877622 bnc#889295 bnc#893454).

  - mm, THP: don't hold mmap_sem in khugepaged when
    allocating THP (bnc#880767, VM Performance).

  - pagecache_limit: batch large nr_to_scan targets
    (bnc#895221).

  - iommu/vt-d: Check return value of acpi_bus_get_device()
    (bnc#903307).

  - rpm/kernel-binary.spec.in: Fix including the secure boot
    cert in /etc/uefi/certs

  - sched: Reduce contention in update_cfs_rq_blocked_load()
    (Scheduler/core performance).

  - x86: use optimized ioresource lookup in ioremap function
    (Boot time optimisations (bnc#895387)).

  - x86: optimize resource lookups for ioremap (Boot time
    optimisations (bnc#895387)).

  - usb: Do not re-read descriptors for wired devices in
    usb_authorize_device() (bnc#904354).

  - netxen: Fix link event handling (bnc#873228).

  - x86, cpu: Detect more TLB configuration -xen (TLB
    Performance).

  - x86/mm: Fix RCU splat from new TLB tracepoints (TLB
    Performance).

  - x86/mm: Set TLB flush tunable to sane value (33) (TLB
    Performance).

  - x86/mm: New tunable for single vs full TLB flush (TLB
    Performance).

  - x86/mm: Add tracepoints for TLB flushes (TLB
    Performance).

  - x86/mm: Unify remote INVLPG code (TLB Performance).

  - x86/mm: Fix missed global TLB flush stat (TLB
    Performance).

  - x86/mm: Rip out complicated, out-of-date, buggy TLB
    flushing (TLB Performance).

  - x86, cpu: Detect more TLB configuration (TLB
    Performance).

  - mm, x86: Revisit tlb_flushall_shift tuning for page
    flushes except on IvyBridge (TLB Performance).

  - x86/mm: Clean up the TLB flushing code (TLB
    Performance).

  - mm: free compound page with correct order (VM
    Functionality).

  - bnx2x: Utilize FW 7.10.51 (bnc#887382).

  - bnx2x: Remove unnecessary internal mem config
    (bnc#887382).

  - rtnetlink: fix oops in
    rtnl_link_get_slave_info_data_size (bnc#901774).

  - dm: do not call dm_sync_table() when creating new
    devices (bnc#901809).

  - [media] uvc: Fix destruction order in uvc_delete()
    (bnc#897736).

  - uas: replace WARN_ON_ONCE() with lockdep_assert_held()
    (FATE#315595).

  - cxgb4/cxgb4vf: Add Devicde ID for two more adapter
    (bsc#903999).

  - cxgb4/cxgb4vf: Add device ID for new adapter and remove
    for dbg adapter (bsc#903999).

  - cxgb4: Adds device ID for few more Chelsio T4 Adapters
    (bsc#903999).

  - cxgb4: Check if rx checksum offload is enabled, while
    reading hardware calculated checksum (bsc#903999).

  - xen-pciback: drop SR-IOV VFs when PF driver unloads
    (bsc#901839).

This update also includes fixes contained in the Linux 3.12.stable
release series, not separately listed here.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6405.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3185.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3610.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3611.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3647.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3673.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-7826.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-7841.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8133.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9090.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9322.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=851603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=853040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=860441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=862957"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=863526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=870498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=873228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=874025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=877622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=879255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=880767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=880892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=881085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=883139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=887046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=887382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=887418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=889295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=889297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=891259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=891619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=892254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=892612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=892650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=892860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=893454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=894057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=894863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=895221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=895387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=895468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=895680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=895983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=896391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=897101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=897736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=897770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=897912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=898234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=898297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=899192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=899489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=899551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=899785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=899787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=899908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=900126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=901090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=901774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=901809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=901925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=902010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=902016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=902346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=902893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=902898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=903279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=903307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=904013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=904077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=904115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=904354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=904871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=905087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=905100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=905296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=905758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=905772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=907818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=908184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=909077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=910251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=910697"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150068-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c7a8e72"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2015-21

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-21

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-21

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2015-21

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-21

SUSE Linux Enterprise Build System Kit 12 :

zypper in -t patch SUSE-SLE-BSK-12-2015-21

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
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
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"kernel-default-man-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-debuginfo-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debuginfo-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debugsource-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-devel-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-syms-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-devel-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-syms-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.32-33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.32-33.1")) flag++;


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
