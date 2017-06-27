#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0178-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83678);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2014-3687", "CVE-2014-3690", "CVE-2014-8559", "CVE-2014-9420", "CVE-2014-9585");
  script_bugtraq_id(70691, 70766, 70854, 71717, 71990);
  script_osvdb_id(113629, 113724, 114044, 116075, 116910);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2015:0178-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 kernel was updated to 3.12.36 to receive
various security and bugfixes.

Following security bugs were fixed :

  - CVE-2014-8559: The d_walk function in fs/dcache.c in the
    Linux kernel through 3.17.2 did not properly maintain
    the semantics of rename_lock, which allowed local users
    to cause a denial of service (deadlock and system hang)
    via a crafted application (bnc#903640).

  - CVE-2014-9420: The rock_continue function in
    fs/isofs/rock.c in the Linux kernel through 3.18.1 did
    not restrict the number of Rock Ridge continuation
    entries, which allowed local users to cause a denial of
    service (infinite loop, and system crash or hang) via a
    crafted iso9660 image (bnc#906545 911325).

  - CVE-2014-3690: arch/x86/kvm/vmx.c in the KVM subsystem
    in the Linux kernel before 3.17.2 on Intel processors
    did not ensure that the value in the CR4 control
    register remained the same after a VM entry, which
    allowed host OS users to kill arbitrary processes or
    cause a denial of service (system disruption) by
    leveraging /dev/kvm access, as demonstrated by
    PR_SET_TSC prctl calls within a modified copy of QEMU
    (bnc#902232).

  - CVE-2014-3687: The sctp_assoc_lookup_asconf_ack function
    in net/sctp/associola.c in the SCTP implementation in
    the Linux kernel through 3.17.2 allowed remote attackers
    to cause a denial of service (panic) via duplicate
    ASCONF chunks that triggered an incorrect uncork within
    the side-effect interpreter (bnc#902349).

  - CVE-2014-9585: The vdso_addr function in
    arch/x86/vdso/vma.c in the Linux kernel through 3.18.2
    did not properly choose memory locations for the vDSO
    area, which made it easier for local users to bypass the
    ASLR protection mechanism by guessing a location at the
    end of a PMD (bnc#912705).

The following non-security bugs were fixed :

  - ACPI idle: permit sparse C-state sub-state numbers
    (bnc#907969).

  - ALSA: hda - verify pin:converter connection on unsol
    event for HSW and VLV.

  - ALSA: hda - verify pin:cvt connection on preparing a
    stream for Intel HDMI codec.

  - ALSA: hda/hdmi - apply Valleyview fix-ups to Cherryview
    display codec.

  - ALSA: hda_intel: Add Device IDs for Intel Sunrise Point
    PCH.

  - ALSA: hda_intel: Add DeviceIDs for Sunrise Point-LP.

  - Btrfs: Disable
    patches.suse/Btrfs-fix-abnormal-long-waiting-in-fsync.pa
    tch (bnc#910697) because it needs to be revisited due
    partial msync behavior.

  - Btrfs: Fix misuse of chunk mutex (bnc#912514).

  - Btrfs: always clear a block group node when removing it
    from the tree (bnc#912514).

  - Btrfs: collect only the necessary ordered extents on
    ranged fsync (bnc#912946).

  - Btrfs: do not access non-existent key when csum tree is
    empty.

  - Btrfs: do not delay inode ref updates during log replay.

  - Btrfs: do not ignore log btree writeback errors
    (bnc#912946).

  - Btrfs: ensure btrfs_prev_leaf does not miss 1 item.

  - Btrfs: ensure deletion from pinned_chunks list is
    protected (bnc#908198).

  - Btrfs: ensure ordered extent errors are not missed on
    fsync (bnc#912946).

  - Btrfs: fix abnormal long waiting in fsync (VM/FS
    Micro-optimisations).

  - Btrfs: fix abnormal long waiting in fsync (bnc#912946).

  - Btrfs: fix crash caused by block group removal
    (bnc#912514).

  - Btrfs: fix freeing used extent after removing empty
    block group (bnc#912514).

  - Btrfs: fix freeing used extents after removing empty
    block group (bnc#912514).

  - Btrfs: fix fs corruption on transaction abort if device
    supports discard (bnc#908198).

  - Btrfs: fix fs mapping extent map leak (bnc#908198).

  - Btrfs: fix invalid block group rbtree access after bg is
    removed (bnc#912514).

  - Btrfs: fix memory leak after block remove + trimming
    (bnc#908198).

  - Btrfs: fix race between fs trimming and block group
    remove/allocation (bnc#908198).

  - Btrfs: fix race between writing free space cache and
    trimming (bnc#908198).

  - Btrfs: fix transaction leak during fsync call.

  - Btrfs: fix unprotected deletion from pending_chunks list
    (bnc#908198).

  - Btrfs: fix unprotected system chunk array insertion
    (bnc#912514).

  - Btrfs: free ulist in qgroup_shared_accounting() error
    path.

  - Btrfs: ioctl, do not re-lock extent range when not
    necessary.

  - Btrfs: make btrfs_abort_transaction consider existence
    of new block groups (bnc#908198).

  - Btrfs: make sure logged extents complete in the current
    transaction V3 (bnc#912946).

  - Btrfs: make sure we wait on logged extents when fsycning
    two subvols (bnc#912946).

  - Btrfs: make xattr replace operations atomic
    (bnc#913466).

  - Btrfs: remove empty block groups automatically
    (bnc#912514).

  - Btrfs: remove unused wait queue in struct extent_buffer.

  - Btrfs: replace EINVAL with ERANGE for resize when
    ULLONG_MAX.

  - Btrfs: use helpers for last_trans_log_full_commit
    instead of opencode (bnc#912946).

  - Drivers: hv: kvp,vss: Fast propagation of userspace
    communication failure.

  - Drivers: hv: util: Properly pack the data for file copy
    functionality.

  - Drivers: hv: util: make struct hv_do_fcopy match Hyper-V
    host messages.

  - Drivers: hv: vmbus: Fix a race condition when
    unregistering a device.

  - Drivers: hv: vss: Introduce timeout for communication
    with userspace.

  - Fixed warning on DP unplugging driver in intel_dp.c
    (bnc#907536).

  - Fixed warning on suspend in intel_display.c
    (bnc#907593).

  - KEYS: Fix stale key registration at error path
    (bnc#908163).

  - PCI/MSI: Add pci_enable_msi_range() and
    pci_enable_msix_range() (bug#912281).

  - PCI/MSI: Add pci_enable_msi_range() and
    pci_enable_msix_range() (bug#912281).

  - Refresh patches.xen/xen3-patch-3.9 (bsc#909829).

  - Remove filesize checks for sync I/O journal commit
    (bnc#800255).

  - SELinux: fix selinuxfs policy file on big endian systems
    (bsc#913233).

  - Tools: hv: vssdaemon: ignore the EBUSY on multiple
    freezing the same partition.

  - Tools: hv: vssdaemon: report freeze errors.

  - Tools: hv: vssdaemon: skip all filesystems mounted
    readonly.

  - Update Xen patches to 3.12.35.

  - Update s390x kabi files again (bnc#903279, LTC#118177)

  - benet: Use pci_enable_msix_range() instead of
    pci_enable_msix() (bug#912281).

  - bfa: check for terminated commands (bnc#906027).

  - cpuidle / menu: Return (-1) if there are no suitable
    states (cpuidle performance).

  - cpuidle / menu: move repeated correction factor check to
    init (cpuidle performance).

  - cpuidle: Do not substract exit latency from assumed
    sleep length (cpuidle performance).

  - cpuidle: Ensure menu coefficients stay within domain
    (cpuidle performance).

  - cpuidle: Move perf multiplier calculation out of the
    selection loop (cpuidle performance).

  - cpuidle: Use actual state latency in menu governor
    (cpuidle performance).

  - cpuidle: menu governor - remove unused macro
    STDDEV_THRESH (cpuidle performance).

  - cpuidle: menu: Call nr_iowait_cpu less times (cpuidle
    performance).

  - cpuidle: menu: Lookup CPU runqueues less (cpuidle
    performance).

  - cpuidle: menu: Use ktime_to_us instead of reinventing
    the wheel (cpuidle performance).

  - cpuidle: menu: Use shifts when calculating averages
    where possible (cpuidle performance).

  - cpuidle: rename expected_us to next_timer_us in menu
    governor (cpuidle performance).

  - crypto: aesni - Add support for 192 & 256 bit keys to
    AESNI RFC4106 (bsc#913387).

  - crypto: kernel oops at insmod of the z90crypt device
    driver (bnc#908057, LTC#119591).

  - cxgb4: Add the MC1 registers to read in the interrupt
    handler (bsc#912290).

  - cxgb4: Allow T4/T5 firmware sizes up to 1MB
    (bsc#912290).

  - cxgb4: Fix FW flash logic using ethtool (bsc#912290).

  - cxgb4: Fix T5 adapter accessing T4 adapter registers
    (bsc#912290).

  - cxgb4: Fix for handling 1Gb/s SFP+ Transceiver Modules
    (bsc#912290).

  - cxgb4: Fix race condition in cleanup (bsc#912290).

  - cxgb4: Free completed tx skbs promptly (bsc#912290).

  - cxgb4: Not need to hold the adap_rcu_lock lock when read
    adap_rcu_list (bsc#912290).

  - cxgb4: Use FW interface to get BAR0 value (bsc#912290).

  - drm/i915: Do a dummy DPCD read before the actual read
    (bnc#907714).

  - drm: add MIPI DSI encoder and connector types
    (bnc#907971).

  - ext4: cache extent hole in extent status tree for
    ext4_da_map_blocks() (bnc#893428).

  - ext4: change LRU to round-robin in extent status tree
    shrinker (bnc#893428).

  - ext4: cleanup flag definitions for extent status tree
    (bnc#893428).

  - ext4: fix block reservation for bigalloc filesystems
    (bnc#893428).

  - ext4: improve extents status tree trace point
    (bnc#893428).

  - ext4: introduce aging to extent status tree
    (bnc#893428).

  - ext4: limit number of scanned extents in status tree
    shrinker (bnc#893428).

  - ext4: move handling of list of shrinkable inodes into
    extent status code (bnc#893428).

  - ext4: track extent status tree shrinker delay statictics
    (bnc#893428).

  - fix kABI after 'x86: use custom
    dma_get_required_mask()'.

  - fsnotify: next_i is freed during fsnotify_unmount_inodes
    (bnc#908904).

  - hv: hv_balloon: avoid memory leak on alloc_error of 2MB
    memory block.

  - hyperv: Add processing of MTU reduced by the host.

  - hyperv: Fix some variable name typos in send-buffer
    init/revoke.

  - hyperv: Fix the total_data_buflen in send path.

  - intel_idle: Add CPU model 54 (Atom N2000 series)
    (bnc#907969).

  - intel_idle: allow sparse sub-state numbering, for Bay
    Trail (bnc#907969).

  - intel_idle: support Bay Trail (bnc#907969).

  - intel_pstate: Add setting voltage value for baytrail P
    states (bnc#907973).

  - intel_pstate: Add support for Baytrail turbo P states
    (bnc#907973).

  - intel_pstate: Fix BYT frequency reporting (bnc#907973).

  - intel_pstate: Fix setting VID (bnc#907973).

  - intel_pstate: Set turbo VID for BayTrail (bnc#907973).

  - intel_pstate: Use LFM bus ratio as min ratio/P state
    (bnc#907973).

  - iommu/vt-d: Fix an off-by-one bug in __domain_mapping()
    (bsc#908825).

  - ipc/sem.c: change memory barrier in sem_lock() to
    smp_rmb() (IPC scalability).

  - isofs: Fix unchecked printing of ER records.

  - kABI: fix for move of d_rcu (bnc#903640 CVE-2014-8559).

  - kABI: protect ipv6.h include in drivers/net.

  - kABI: protect rmap include in mm/truncate.c.

  - kABI: protect struct iwl_trans.

  - kABI: protect struct pci_dev.

  - kABI: protect struct user_namespace.

  - kABI: protect user_namespace.h include in
    kernel/groups.c.

  - kABI: reintroduce generic_write_sync.

  - kABI: uninline of_property_count_string* functions.
    Omitted ppc64le kabi fix for 3.12.33.

  - kernel: kprobes instruction corruption (bnc#908057,
    LTC#119330).

  - kernel: reduce function tracer overhead (bnc#903279,
    LTC#118177).

  - kgr: allow to search various types of struct
    kgr_patch_fun.

  - kgr: be consistent when applying patches on loaded
    modules.

  - kgr: fix replace_all.

  - kgr: fix typo in error message.

  - kgr: fix unwinder and user addresses (bnc#908803).

  - kgr: handle IRQ context using global variable.

  - kgr: mark even more kthreads (bnc#905087 bnc#906140).

  - kgr: prevent recursive loops of stubs in ftrace.

  - kgr: set revert slow state for all reverted symbols when
    loading patched module.

  - kgr: unregister only the used ftrace ops when removing a
    patched module.

  - kprobes: introduce weak arch_check_ftrace_location()
    helper function (bnc#903279, LTC#118177).

  - kvm: Do not expose MONITOR cpuid as available
    (bnc#887597)

  - lpfc: Fix race on command completion (bnc#906027).

  - macvlan: allow setting LRO independently of lower device
    (bnc#829110 bnc#891277 bnc#904053).

  - mm, cma: drain single zone pcplists (VM Performance,
    bnc#904177).

  - mm, compaction: always update cached scanner positions
    (VM Performance, bnc#904177).

  - mm, compaction: defer each zone individually instead of
    preferred zone (VM Performance, bnc#904177).

  - mm, compaction: defer only on COMPACT_COMPLETE (VM
    Performance, bnc#904177).

  - mm, compaction: do not count compact_stall if all zones
    skipped compaction (VM Performance, bnc#904177).

  - mm, compaction: do not recheck suitable_migration_target
    under lock (VM Performance, bnc#904177).

  - mm, compaction: khugepaged should not give up due to
    need_resched() (VM Performance, bnc#904177).

  - mm, compaction: more focused lru and pcplists draining
    (VM Performance, bnc#904177).

  - mm, compaction: move pageblock checks up from
    isolate_migratepages_range() (VM Performance,
    bnc#904177).

  - mm, compaction: pass classzone_idx and alloc_flags to
    watermark checking (VM Performance, bnc#904177).

  - mm, compaction: pass gfp mask to compact_control (VM
    Cleanup, bnc#904177).

  - mm, compaction: periodically drop lock and restore IRQs
    in scanners (VM Performance, bnc#904177).

  - mm, compaction: prevent infinite loop in compact_zone
    (VM Functionality, bnc#904177).

  - mm, compaction: reduce zone checking frequency in the
    migration scanner (VM Performance, bnc#904177).

  - mm, compaction: remember position within pageblock in
    free pages scanner (VM Performance, bnc#904177).

  - mm, compaction: simplify deferred compaction (VM
    Performance, bnc#904177).

  - mm, compaction: skip buddy pages by their order in the
    migrate scanner (VM Performance, bnc#904177).

  - mm, compaction: skip rechecks when lock was already held
    (VM Performance, bnc#904177).

  - mm, memory_hotplug/failure: drain single zone pcplists
    (VM Performance, bnc#904177).

  - mm, page_isolation: drain single zone pcplists (VM
    Performance, bnc#904177).

  - mm, thp: avoid excessive compaction latency during fault
    (VM Performance, bnc#904177).

  - mm, thp: restructure thp avoidance of light synchronous
    migration (VM Performance, bnc#904177).

  - mm/compaction.c: avoid premature range skip in
    isolate_migratepages_range (VM Functionality,
    bnc#904177).

  - mm/compaction: skip the range until proper target
    pageblock is met (VM Performance, bnc#904177).

  - mm/vmscan.c: use DIV_ROUND_UP for calculation of zones
    balance_gap and correct comments (VM Cleanup,
    bnc#904177).

  - mm/vmscan: do not check compaction_ready on promoted
    zones (VM Cleanup, bnc#904177).

  - mm/vmscan: restore sc->gfp_mask after promoting it to
    __GFP_HIGHMEM (VM Cleanup, bnc#904177).

  - mm: Disable
    patches.suse/msync-fix-incorrect-fstart-calculation.patc
    h (bnc#910697) because it needs to be revisited due
    partial msync behavior.

  - mm: Disabled
    patches.suse/mm-msync.c-sync-only-the-requested-range-in
    -msync.patch (bnc#910697) because it needs to be
    revisited due partial msync behavior.

  - mm: improve documentation of page_order (VM Cleanup,
    bnc#904177).

  - mm: introduce single zone pcplists drain (VM
    Performance, bnc#904177).

  - mm: memcontrol: remove hierarchy restrictions for
    swappiness and oom_control (VM Cleanup, bnc#904177).

  - mm: page_alloc: determine migratetype only once (VM
    Performance, bnc#904177).

  - mm: rename allocflags_to_migratetype for clarity (VM
    Cleanup, bnc#904177).

  - mm: unmapped page migration avoid unmap+remap overhead
    (MM performance).

  - mm: vmscan: clean up struct scan_control (VM Cleanup,
    bnc#904177).

  - mm: vmscan: move call to shrink_slab() to shrink_zones()
    (VM Cleanup, bnc#904177).

  - mm: vmscan: move swappiness out of scan_control (VM
    Cleanup, bnc#904177).

  - mm: vmscan: remove all_unreclaimable() (VM Cleanup,
    bnc#904177).

  - mm: vmscan: remove remains of kswapd-managed
    zone->all_unreclaimable (VM Cleanup, bnc#904177).

  - mm: vmscan: remove shrink_control arg from
    do_try_to_free_pages() (VM Cleanup, bnc#904177).

  - mm: vmscan: rework compaction-ready signaling in direct
    reclaim (VM Cleanup, bnc#904177).

  - msync: fix incorrect fstart calculation (VM/FS
    Micro-optimisations).

  - net, sunrpc: suppress allocation warning in rpc_malloc()
    (bnc#904659).

  - net: Find the nesting level of a given device by type
    (bnc#829110 bnc#891277 bnc#904053).

  - net: Hyper-V: Deletion of an unnecessary check before
    the function call 'vfree'.

  - net: generic dev_disable_lro() stacked device handling
    (bnc#829110 bnc#891277 bnc#904053).

  - nvme: Add missing hunk from backport (bnc#873252).

  - parport: parport_pc, do not remove parent devices early
    (bnc#856659).

  - patches.suse/supported-flag: fix mis-reported supported
    status (bnc#809493).

  - patches.xen/xen-privcmd-hcall-preemption: Fix EFLAGS.IF
    check.

  - powerpc/fadump: Fix endianess issues in firmware
    assisted dump handling (bsc#889192).

  - powerpc/pseries/hvcserver: Fix endian issue in
    hvcs_get_partner_info (bsc#912129).

  - powerpc/pseries: Make CPU hotplug path endian safe
    (bsc#907069).

  - powerpc: fix dlpar memory

  - pseries: Fix endian issues in cpu hot-removal
    (bsc#907069).

  - pseries: Fix endian issues in onlining cpu threads
    (bsc#907069).

  - rpm/constraints.in: Require 10GB disk space on POWER A
    debuginfo build currently requires about 8.5 GB on
    POWER. Also, require at least 8 CPUs, so that builds do
    not get accidentally scheduled on slow machines.

  - rpm/gitlog-fixups: Fix invalid address in two commits

  - s390/ftrace,kprobes: allow to patch first instruction
    (bnc#903279, LTC#118177).

  - s390/ftrace: add HAVE_DYNAMIC_FTRACE_WITH_REGS support
    (bnc#903279, LTC#118177).

  - s390/ftrace: add code replacement sanity checks
    (bnc#903279, LTC#118177).

  - s390/ftrace: enforce DYNAMIC_FTRACE if FUNCTION_TRACER
    is selected (bnc#903279, LTC#118177).

  - s390/ftrace: optimize function graph caller code
    (bnc#903279, LTC#118177).

  - s390/ftrace: optimize mcount code (bnc#903279,
    LTC#118177).

  - s390/ftrace: remove 31 bit ftrace support (bnc#903279,
    LTC#118177).

  - s390/ftrace: remove check of obsolete variable
    function_trace_stop (bnc#903279, LTC#118177).

  - s390/ftrace: revert mcount_adjust change (bnc#903279,
    LTC#118177).

  - s390/ftrace: simplify enabling/disabling of
    ftrace_graph_caller (bnc#903279, LTC#118177).

  - s390: pass march flag to assembly files as well
    (bnc#903279, LTC#118177).

  - sched/fair: cleanup: Remove useless assignment in
    select_task_rq_fair() (cpuidle performance).

  - scripts/tags.sh: Do not specify kind-spec for emacs
    ctags/etags.

  - scripts/tags.sh: fix DEFINE_HASHTABLE in emacs case.

  - scripts/tags.sh: include compat_sys_* symbols in the
    generated tags.

  - scsi: call device handler for failed TUR command
    (bnc#895814).

  - series.conf: remove orphan bnc comments

  - storvsc: ring buffer failures may result in I/O freeze.

  - supported.conf: mark tcm_qla2xxx as supported Has not
    been ported from SLES11 SP3 automatically.

  - tags.sh: Fixup regex definition for etags.

  - tcm_loop: Wrong I_T nexus association (bnc#907325).

  - tools: hv: ignore ENOBUFS and ENOMEM in the KVP daemon.

  - tools: hv: introduce -n/--no-daemon option.

  - udf: Check component length before reading it.

  - udf: Check path length when reading symlink.

  - udf: Verify i_size when loading inode.

  - udf: Verify symlink size before loading it.

  - vmscan: memcg: always use swappiness of the reclaimed
    memcg (VM Cleanup, bnc#904177).

  - x86, cpu: Detect more TLB configuration (TLB
    Performance).

  - x86-64/MCE: flip CPU and bank numbers in log message.

  - x86/UV: Fix conditional in gru_exit() (bsc#909095).

  - x86/early quirk: use gen6 stolen detection for VLV
    (bnc#907970).

  - x86/efi: Do not export efi runtime map in case old map
    (bsc#904969).

  - x86/mm: Add tracepoints for TLB flushes (TLB
    Performance).

  - x86/mm: Rip out complicated, out-of-date, buggy TLB
    flushing (TLB Performance).

  - x86/uv: Update the UV3 TLB shootdown logic (bsc#909092).

  - x86: UV BAU: Avoid NULL pointer reference in
    ptc_seq_show (bsc#911181).

  - x86: UV BAU: Increase maximum CPUs per socket/hub
    (bsc#911181).

  - x86: fix step size adjustment during initial memory
    mapping (bsc#910249).

  - x86: use custom dma_get_required_mask().

  - x86: use optimized ioresource lookup in ioremap function
    (Boot time optimisations (bnc#895387)).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3687.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3690.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8559.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9585.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=800255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=809493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=829110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=856659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=862374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=873252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=875220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=884407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=887108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=887597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=889192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=891086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=891277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=893428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=895387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=895814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=902232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=902346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=902349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=903279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=903640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=904053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=904177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=904659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=904969"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=906027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=906140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=906545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=907069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=907325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=907536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=907593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=907714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=907818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=907969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=907970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=907971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=907973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=908057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=908163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=908198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=908803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=908825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=908904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=909077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=909092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=909095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=909829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=910249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=910697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=911181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=911325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=912129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=912278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=912281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=912290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=912514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=912705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=912946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=913233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=913387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=913466"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150178-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f92c399"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2015-48

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-48

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-48

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2015-48

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-48

SUSE Linux Enterprise Build System Kit 12 :

zypper in -t patch SUSE-SLE-BSK-12-2015-48

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/21");
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
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"kernel-default-man-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-debuginfo-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debuginfo-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debugsource-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-devel-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-syms-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-devel-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-syms-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.36-38.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.36-38.1")) flag++;


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
