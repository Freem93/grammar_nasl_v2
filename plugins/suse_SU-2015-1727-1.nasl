#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1727-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(86378);
  script_version("$Revision: 2.17 $");
  script_cvs_date("$Date: 2016/10/28 21:03:38 $");

  script_cve_id("CVE-2015-5156", "CVE-2015-5157", "CVE-2015-5283", "CVE-2015-5697", "CVE-2015-6252", "CVE-2015-6937", "CVE-2015-7613");
  script_bugtraq_id(76005);
  script_osvdb_id(125208, 125431, 125846, 126403, 127759, 128012, 128379);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel-source (SUSE-SU-2015:1727-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 kernel was updated to 3.12.48-52.27 to
receive various security and bugfixes.

Following security bugs were fixed :

  - CVE-2015-7613: A flaw was found in the Linux kernel IPC
    code that could lead to arbitrary code execution. The
    ipc_addid() function initialized a shared object that
    has unset uid/gid values. Since the fields are not
    initialized, the check can falsely succeed. (bsc#948536)

  - CVE-2015-5156: When a guests KVM network devices is in a
    bridge configuration the kernel can create a situation
    in which packets are fragmented in an unexpected
    fashion. The GRO functionality can create a situation in
    which multiple SKB's are chained together in a single
    packets fraglist (by design). (bsc#940776)

  - CVE-2015-5157: arch/x86/entry/entry_64.S in the Linux
    kernel before 4.1.6 on the x86_64 platform mishandles
    IRET faults in processing NMIs that occurred during
    userspace execution, which might allow local users to
    gain privileges by triggering an NMI (bsc#938706).

  - CVE-2015-6252: A flaw was found in the way the Linux
    kernel's vhost driver treated userspace provided log
    file descriptor when processing the VHOST_SET_LOG_FD
    ioctl command. The file descriptor was never released
    and continued to consume kernel memory. A privileged
    local user with access to the /dev/vhost-net files could
    use this flaw to create a denial-of-service attack
    (bsc#942367).

  - CVE-2015-5697: The get_bitmap_file function in
    drivers/md/md.c in the Linux kernel before 4.1.6 does
    not initialize a certain bitmap data structure, which
    allows local users to obtain sensitive information from
    kernel memory via a GET_BITMAP_FILE ioctl call.
    (bnc#939994)

  - CVE-2015-6937: A NULL pointer dereference flaw was found
    in the Reliable Datagram Sockets (RDS) implementation
    allowing a local user to cause system DoS. A
    verification was missing that the underlying transport
    exists when a connection was created. (bsc#945825)

  - CVE-2015-5283: A NULL pointer dereference flaw was found
    in SCTP implementation allowing a local user to cause
    system DoS. Creation of multiple sockets in parallel
    when system doesn't have SCTP module loaded can lead to
    kernel panic. (bsc#947155)

The following non-security bugs were fixed :

  - ALSA: hda - Abort the probe without i915 binding for
    HSW/BDW (bsc#936556).

  - Btrfs: Backport subvolume mount option handling
    (bsc#934962)

  - Btrfs: Handle unaligned length in extent_same
    (bsc#937609).

  - Btrfs: advertise which crc32c implementation is being
    used on mount (bsc#946057).

  - Btrfs: allow mounting btrfs subvolumes with different
    ro/rw options.

  - Btrfs: check if previous transaction aborted to avoid fs
    corruption (bnc#942509).

  - Btrfs: clean up error handling in mount_subvol()
    (bsc#934962).

  - Btrfs: cleanup orphans while looking up default
    subvolume (bsc#914818).

  - Btrfs: do not update mtime/ctime on deduped inodes
    (bsc#937616).

  - Btrfs: fail on mismatched subvol and subvolid mount
    options (bsc#934962).

  - Btrfs: fix chunk allocation regression leading to
    transaction abort (bnc#938550).

  - Btrfs: fix clone / extent-same deadlocks (bsc#937612).

  - Btrfs: fix crash on close_ctree() if cleaner starts new
    transaction (bnc#938891).

  - Btrfs: fix deadlock with extent-same and readpage
    (bsc#937612).

  - Btrfs: fix file corruption after cloning inline extents
    (bnc#942512).

  - Btrfs: fix file read corruption after extent cloning and
    fsync (bnc#946902).

  - Btrfs: fix find_free_dev_extent() malfunction in case
    device tree has hole (bnc#938550).

  - Btrfs: fix hang when failing to submit bio of directIO
    (bnc#942685).

  - Btrfs: fix list transaction->pending_ordered corruption
    (bnc#938893).

  - Btrfs: fix memory corruption on failure to submit bio
    for direct IO (bnc#942685).

  - Btrfs: fix memory leak in the extent_same ioctl
    (bsc#937613).

  - Btrfs: fix put dio bio twice when we submit dio bio fail
    (bnc#942685).

  - Btrfs: fix race between balance and unused block group
    deletion (bnc#938892).

  - Btrfs: fix range cloning when same inode used as source
    and destination (bnc#942511).

  - Btrfs: fix read corruption of compressed and shared
    extents (bnc#946906).

  - Btrfs: fix uninit variable in clone ioctl (bnc#942511).

  - Btrfs: fix use-after-free in mount_subvol().

  - Btrfs: fix wrong check for btrfs_force_chunk_alloc()
    (bnc#938550).

  - Btrfs: lock superblock before remounting for rw subvol
    (bsc#934962).

  - Btrfs: pass unaligned length to btrfs_cmp_data()
    (bsc#937609).

  - Btrfs: remove all subvol options before mounting
    top-level (bsc#934962).

  - Btrfs: show subvol= and subvolid= in /proc/mounts
    (bsc#934962).

  - Btrfs: unify subvol= and subvolid= mounting
    (bsc#934962).

  - Btrfs: fill ->last_trans for delayed inode in
    btrfs_fill_inode (bnc#942925).

  - Btrfs: fix metadata inconsistencies after directory
    fsync (bnc#942925).

  - Btrfs: fix stale dir entries after removing a link and
    fsync (bnc#942925).

  - Btrfs: fix stale dir entries after unlink, inode
    eviction and fsync (bnc#942925).

  - Btrfs: fix stale directory entries after fsync log
    replay (bnc#942925).

  - Btrfs: make btrfs_search_forward return with nodes
    unlocked (bnc#942925).

  - Btrfs: support NFSv2 export (bnc#929871).

  - Btrfs: update fix for read corruption of compressed and
    shared extents (bsc#948256).

  - Drivers: hv: do not do hypercalls when hypercall_page is
    NULL.

  - Drivers: hv: vmbus: add special crash handler.

  - Drivers: hv: vmbus: add special kexec handler.

  - Drivers: hv: vmbus: remove hv_synic_free_cpu() call from
    hv_synic_cleanup().

  - Input: evdev - do not report errors form flush()
    (bsc#939834).

  - Input: synaptics - do not retrieve the board id on old
    firmwares (bsc#929092).

  - Input: synaptics - log queried and quirked dimension
    values (bsc#929092).

  - Input: synaptics - query min dimensions for fw v8.1.

  - Input: synaptics - remove X1 Carbon 3rd gen from the
    topbuttonpad list (bsc#929092).

  - Input: synaptics - remove X250 from the topbuttonpad
    list.

  - Input: synaptics - remove obsolete min/max quirk for
    X240 (bsc#929092).

  - Input: synaptics - skip quirks when post-2013 dimensions
    (bsc#929092).

  - Input: synaptics - split synaptics_resolution(), query
    first (bsc#929092).

  - Input: synaptics - support min/max board id in
    min_max_pnpid_table (bsc#929092).

  - NFS: Make sure XPRT_CONNECTING gets cleared when needed
    (bsc#946309).

  - NFSv4: do not set SETATTR for O_RDONLY|O_EXCL
    (bsc#939716).

  - PCI: Move MPS configuration check to
    pci_configure_device() (bsc#943313).

  - PCI: Set MPS to match upstream bridge (bsc#943313).

  - SCSI: fix regression in scsi_send_eh_cmnd()
    (bsc#930813).

  - SCSI: fix scsi_error_handler vs. scsi_host_dev_release
    race (bnc#942204).

  - SCSI: vmw_pvscsi: Fix pvscsi_abort() function
    (bnc#940398).

  - UAS: fixup for remaining use of dead_list (bnc#934942).

  - USB: storage: use %*ph specifier to dump small buffers
    (bnc#934942).

  - aio: fix reqs_available handling (bsc#943378).

  - audit: do not generate loginuid log when audit disabled
    (bsc#941098).

  - blk-merge: do not compute bi_phys_segments from bi_vcnt
    for cloned bio (bnc#934430).

  - blk-merge: fix blk_recount_segments (bnc#934430).

  - blk-merge: recaculate segment if it isn't less than max
    segments (bnc#934430).

  - block: add queue flag for disabling SG merging
    (bnc#934430).

  - block: blk-merge: fix blk_recount_segments()
    (bnc#934430).

  - config: disable CONFIG_TCM_RBD on ppc64le and s390x

  - cpufreq: intel_pstate: Add CPU ID for Braswell
    processor.

  - dlm: fix missing endian conversion of rcom_status flags
    (bsc#940679).

  - dm cache mq: fix memory allocation failure for large
    cache devices (bsc#942707).

  - drm/i915: Avoid race of intel_crt_detect_hotplug() with
    HPD interrupt (bsc#942938).

  - drm/i915: Make hpd arrays big enough to avoid out of
    bounds access (bsc#942938).

  - drm/i915: Only print hotplug event message when hotplug
    bit is set (bsc#942938).

  - drm/i915: Queue reenable timer also when
    enable_hotplug_processing is false (bsc#942938).

  - drm/i915: Use an interrupt save spinlock in
    intel_hpd_irq_handler() (bsc#942938).

  - drm/radeon: fix hotplug race at startup (bsc#942307).

  - ethtool, net/mlx4_en: Add 100M, 20G, 56G speeds ethtool
    reporting support (bsc#945710).

  - hrtimer: prevent timer interrupt DoS (bnc#886785).

  - hv: fcopy: add memory barrier to propagate state
    (bnc#943529).

  - inotify: Fix nested sleeps in inotify_read()
    (bsc#940925).

  - intel_pstate: Add CPU IDs for Broadwell processors.

  - intel_pstate: Add CPUID for BDW-H CPU.

  - intel_pstate: Add support for SkyLake.

  - intel_pstate: Correct BYT VID values (bnc#907973).

  - intel_pstate: Remove periodic P state boost
    (bnc#907973).

  - intel_pstate: add sample time scaling (bnc#907973,
    bnc#924722, bnc#916543).

  - intel_pstate: don't touch turbo bit if turbo disabled or
    unavailable (bnc#907973).

  - intel_pstate: remove setting P state to MAX on init
    (bnc#907973).

  - intel_pstate: remove unneeded sample buffers
    (bnc#907973).

  - intel_pstate: set BYT MSR with wrmsrl_on_cpu()
    (bnc#907973).

  - ipr: Fix incorrect trace indexing (bsc#940912).

  - ipr: Fix invalid array indexing for HRRQ (bsc#940912).

  - iwlwifi: dvm: drop non VO frames when flushing
    (bsc#940545).

  - kABI workaround for ieee80211_ops.flush argument change
    (bsc#940545).

  - kconfig: Do not print status messages in make -s mode
    (bnc#942160).

  - kernel/modsign_uefi.c: Check for EFI_RUNTIME_SERVICES in
    load_uefi_certs (bsc#856382).

  - kernel: do full redraw of the 3270 screen on reconnect
    (bnc#943476, LTC#129509).

  - kexec: define kexec_in_progress in !CONFIG_KEXEC case.

  - kvm: Use WARN_ON_ONCE for missing X86_FEATURE_NRIPS
    (bsc#947537).

  - lpfc: Fix scsi prep dma buf error (bsc#908950).

  - mac80211: add vif to flush call (bsc#940545).

  - md/bitmap: do not abuse i_writecount for bitmap files
    (bsc#943270).

  - md/bitmap: protect clearing of ->bitmap by mddev->lock
    (bnc#912183).

  - md/raid5: use ->lock to protect accessing raid5 sysfs
    attributes (bnc#912183).

  - md: fix problems with freeing private data after ->run
    failure (bnc#912183).

  - md: level_store: group all important changes into one
    place (bnc#912183).

  - md: move GET_BITMAP_FILE ioctl out from mddev_lock
    (bsc#943270).

  - md: protect ->pers changes with mddev->lock
    (bnc#912183).

  - md: remove mddev_lock from rdev_attr_show()
    (bnc#912183).

  - md: remove mddev_lock() from md_attr_show()
    (bnc#912183).

  - md: remove need for mddev_lock() in md_seq_show()
    (bnc#912183).

  - md: split detach operation out from ->stop (bnc#912183).

  - md: tidy up set_bitmap_file (bsc#943270).

  - megaraid_sas: Handle firmware initialization after fast
    boot (bsc#922071).

  - mfd: lpc_ich: Assign subdevice ids automatically
    (bnc#898159).

  - mm: filemap: Avoid unnecessary barriers and waitqueue
    lookups -fix (VM/FS Performance (bnc#941951)).

  - mm: make page pfmemalloc check more robust (bnc#920016).

  - mm: numa: disable change protection for vma(VM_HUGETLB)
    (bnc#943573).

  - netfilter: nf_conntrack_proto_sctp: minimal multihoming
    support (bsc#932350).

  - net/mlx4_core: Add ethernet backplane autoneg device
    capability (bsc#945710).

  - net/mlx4_core: Introduce ACCESS_REG CMD and
    eth_prot_ctrl dev cap (bsc#945710).

  - net/mlx4_en: Use PTYS register to query ethtool settings
    (bsc#945710).

  - net/mlx4_en: Use PTYS register to set ethtool settings
    (Speed) (bsc#945710).

  - rcu: Reject memory-order-induced stall-warning false
    positives (bnc#941908).

  - s390/dasd: fix kernel panic when alias is set offline
    (bnc#940965, LTC#128595).

  - sched: Fix KMALLOC_MAX_SIZE overflow during cpumask
    allocation (bnc#939266).

  - sched: Fix cpu_active_mask/cpu_online_mask race
    (bsc#936773).

  - sched, numa: do not hint for NUMA balancing on
    VM_MIXEDMAP mappings (bnc#943573).

  - uas: Add US_FL_MAX_SECTORS_240 flag (bnc#934942).

  - uas: Add response iu handling (bnc#934942).

  - uas: Add uas_get_tag() helper function (bnc#934942).

  - uas: Check against unexpected completions (bnc#934942).

  - uas: Cleanup uas_log_cmd_state usage (bnc#934942).

  - uas: Do not log urb status error on cancellation
    (bnc#934942).

  - uas: Do not use scsi_host_find_tag (bnc#934942).

  - uas: Drop COMMAND_COMPLETED flag (bnc#934942).

  - uas: Drop all references to a scsi_cmnd once it has been
    aborted (bnc#934942).

  - uas: Drop inflight list (bnc#934942).

  - uas: Fix memleak of non-submitted urbs (bnc#934942).

  - uas: Fix resetting flag handling (bnc#934942).

  - uas: Free data urbs on completion (bnc#934942).

  - uas: Log error codes when logging errors (bnc#934942).

  - uas: Reduce number of function arguments for
    uas_alloc_foo functions (bnc#934942).

  - uas: Remove cmnd reference from the cmd urb
    (bnc#934942).

  - uas: Remove support for old sense ui as used in
    pre-production hardware (bnc#934942).

  - uas: Remove task-management / abort error handling code
    (bnc#934942).

  - uas: Set max_sectors_240 quirk for ASM1053 devices
    (bnc#934942).

  - uas: Simplify reset / disconnect handling (bnc#934942).

  - uas: Simplify unlink of data urbs on error (bnc#934942).

  - uas: Use scsi_print_command (bnc#934942).

  - uas: pre_reset and suspend: Fix a few races
    (bnc#934942).

  - uas: zap_pending: data urbs should have completed at
    this time (bnc#934942).

  - x86/kernel: Do not reserve crashkernel high memory if
    crashkernel low memory reserving failed (bsc#939145).

  - x86/smpboot: Check for cpu_active on cpu initialization
    (bsc#932285).

  - x86/smpboot: Check for cpu_active on cpu initialization
    (bsc#936773).

  - xhci: Workaround for PME stuck issues in Intel xhci
    (bnc#944028).

  - xhci: rework cycle bit checking for new dequeue pointers
    (bnc#944028).

  - xfs: Fix file type directory corruption for btree
    directories (bsc#941305).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/856382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/886785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/898159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/907973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/908950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/912183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/916543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936773"
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
    value:"https://bugzilla.suse.com/938550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/941098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/941305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/941908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/941951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/948536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5156.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5157.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5283.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5697.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6252.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6937.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7613.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151727-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f62582a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2015-668=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-668=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-668=1

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2015-668=1

SUSE Linux Enterprise Live Patching 12 :

zypper in -t patch SUSE-SLE-Live-Patching-12-2015-668=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-668=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/14");
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
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.48-52.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-3.12.48-52.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.48-52.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.48-52.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.48-52.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.48-52.27.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"kernel-default-man-3.12.48-52.27.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-3.12.48-52.27.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-3.12.48-52.27.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-debuginfo-3.12.48-52.27.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debuginfo-3.12.48-52.27.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debugsource-3.12.48-52.27.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-devel-3.12.48-52.27.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-syms-3.12.48-52.27.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-3.12.48-52.27.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.48-52.27.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.48-52.27.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-devel-3.12.48-52.27.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-3.12.48-52.27.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.48-52.27.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-syms-3.12.48-52.27.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.48-52.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.48-52.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.48-52.27.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.48-52.27.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-source");
}
