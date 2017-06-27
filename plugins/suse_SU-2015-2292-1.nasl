#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2292-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87495);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2015-0272", "CVE-2015-2925", "CVE-2015-5156", "CVE-2015-7799", "CVE-2015-7872", "CVE-2015-7990", "CVE-2015-8215");
  script_bugtraq_id(73926);
  script_osvdb_id(120327, 125846, 127518, 127759, 128845, 129330);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2015:2292-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 SP1 kernel was updated to 3.12.51 to
receive various security and bugfixes.

Following features were added :

  - hwrng: Add a driver for the hwrng found in power7+
    systems (fate#315784).

Following security bugs were fixed :

  - CVE-2015-8215: net/ipv6/addrconf.c in the IPv6 stack in
    the Linux kernel did not validate attempted changes to
    the MTU value, which allowed context-dependent attackers
    to cause a denial of service (packet loss) via a value
    that is (1) smaller than the minimum compliant value or
    (2) larger than the MTU of an interface, as demonstrated
    by a Router Advertisement (RA) message that is not
    validated by a daemon, a different vulnerability than
    CVE-2015-0272. (bsc#955354)

  - CVE-2015-5156: The virtnet_probe function in
    drivers/net/virtio_net.c in the Linux kernel attempted
    to support a FRAGLIST feature without proper memory
    allocation, which allowed guest OS users to cause a
    denial of service (buffer overflow and memory
    corruption) via a crafted sequence of fragmented packets
    (bnc#940776).

  - CVE-2015-7872: The key_gc_unused_keys function in
    security/keys/gc.c in the Linux kernel allowed local
    users to cause a denial of service (OOPS) via crafted
    keyctl commands (bnc#951440).

  - CVE-2015-7799: The slhc_init function in
    drivers/net/slip/slhc.c in the Linux kernel did not
    ensure that certain slot numbers are valid, which
    allowed local users to cause a denial of service (NULL
    pointer dereference and system crash) via a crafted
    PPPIOCSMAXCID ioctl call (bnc#949936).

  - CVE-2015-2925: The prepend_path function in fs/dcache.c
    in the Linux kernel did not properly handle rename
    actions inside a bind mount, which allowed local users
    to bypass an intended container protection mechanism by
    renaming a directory, related to a 'double-chroot attack
    (bnc#926238).

  - CVE-2015-7990: RDS: Verify the underlying transport
    exists before creating a connection, preventing possible
    DoS (bsc#952384).

The following non-security bugs were fixed :

  - af_iucv: avoid path quiesce of severed path in
    shutdown() (bnc#954986, LTC#131684).

  - alsa: hda - Disable 64bit address for Creative HDA
    controllers (bnc#814440).

  - alsa: hda - Fix noise problems on Thinkpad T440s
    (boo#958504).

  - alsa: hda - Fix noise problems on Thinkpad T440s
    (boo#958504).

  - apparmor: allow SYS_CAP_RESOURCE to be sufficient to
    prlimit another task (bsc#921949).

  - audit: correctly record file names with different path
    name types (bsc#950013).

  - audit: create private file name copies when auditing
    inodes (bsc#950013).

  - bcache: Add btree_insert_node() (bnc#951638).

  - bcache: Add explicit keylist arg to btree_insert()
    (bnc#951638).

  - bcache: backing device set to clean after finishing
    detach (bsc#951638).

  - bcache: backing device set to clean after finishing
    detach (bsc#951638).

  - bcache: Clean up keylist code (bnc#951638).

  - bcache: Convert btree_insert_check_key() to
    btree_insert_node() (bnc#951638).

  - bcache: Convert bucket_wait to wait_queue_head_t
    (bnc#951638).

  - bcache: Convert try_wait to wait_queue_head_t
    (bnc#951638).

  - bcache: Explicitly track btree node's parent
    (bnc#951638).

  - bcache: Fix a bug when detaching (bsc#951638).

  - bcache: Fix a lockdep splat in an error path
    (bnc#951638).

  - bcache: Fix a shutdown bug (bsc#951638).

  - bcache: Fix more early shutdown bugs (bsc#951638).

  - bcache: Fix sysfs splat on shutdown with flash only devs
    (bsc#951638).

  - bcache: Insert multiple keys at a time (bnc#951638).

  - bcache: kill closure locking usage (bnc#951638).

  - bcache: Refactor journalling flow control (bnc#951638).

  - bcache: Refactor request_write() (bnc#951638).

  - bcache: Use blkdev_issue_discard() (bnc#951638).

  - btrfs: Adjust commit-transaction condition to avoid
    NO_SPACE more (bsc#958647).

  - btrfs: Adjust commit-transaction condition to avoid
    NO_SPACE more (bsc#958647).

  - btrfs: cleanup: remove no-used alloc_chunk in
    btrfs_check_data_free_space() (bsc#958647).

  - btrfs: cleanup: remove no-used alloc_chunk in
    btrfs_check_data_free_space() (bsc#958647).

  - btrfs: fix condition of commit transaction (bsc#958647).

  - btrfs: fix condition of commit transaction (bsc#958647).

  - btrfs: fix file corruption and data loss after cloning
    inline extents (bnc#956053).

  - btrfs: Fix out-of-space bug (bsc#958647).

  - btrfs: Fix out-of-space bug (bsc#958647).

  - btrfs: Fix tail space processing in
    find_free_dev_extent() (bsc#958647).

  - btrfs: Fix tail space processing in
    find_free_dev_extent() (bsc#958647).

  - btrfs: fix the number of transaction units needed to
    remove a block group (bsc#958647).

  - btrfs: fix the number of transaction units needed to
    remove a block group (bsc#958647).

  - btrfs: fix truncation of compressed and inlined extents
    (bnc#956053).

  - btrfs: Set relative data on clear
    btrfs_block_group_cache->pinned (bsc#958647).

  - btrfs: Set relative data on clear
    btrfs_block_group_cache->pinned (bsc#958647).

  - btrfs: use global reserve when deleting unused block
    group after ENOSPC (bsc#958647).

  - btrfs: use global reserve when deleting unused block
    group after ENOSPC (bsc#958647).

  - cache: Fix sysfs splat on shutdown with flash only devs
    (bsc#951638).

  - cpu: Defer smpboot kthread unparking until CPU known to
    scheduler (bsc#936773).

  - cpusets, isolcpus: exclude isolcpus from load balancing
    in cpusets (bsc#957395).

  - cxgb4i: Increased the value of MAX_IMM_TX_PKT_LEN from
    128 to 256 bytes (bsc#950580).

  - dlm: make posix locks interruptible, (bsc#947241).

  - dmapi: Fix xfs dmapi to not unlock & lock XFS_ILOCK_EXCL
    (bsc#949744).

  - dm: do not start current request if it would've merged
    with the previous (bsc#904348).

  - dm: impose configurable deadline for dm_request_fn's
    merge heuristic (bsc#904348).

  - dm-snap: avoid deadock on s->lock when a read is split
    (bsc#939826).

  - dm sysfs: introduce ability to add writable attributes
    (bsc#904348).

  - drm: Allocate new master object when client becomes
    master (bsc#956876, bsc#956801).

  - drm: Fix KABI of 'struct drm_file' (bsc#956876,
    bsc#956801).

  - drm/i915: add hotplug activation period to hotplug
    update mask (bsc#953980).

  - drm/i915: clean up backlight conditional build
    (bsc#941113).

  - drm/i915: debug print on backlight register
    (bsc#941113).

  - drm/i915: do full backlight setup at enable time
    (bsc#941113).

  - drm/i915: do not save/restore backlight registers in KMS
    (bsc#941113).

  - drm/i915: Eliminate lots of WARNs when there's no
    backlight present (bsc#941113).

  - drm/i915: fix gen2-gen3 backlight set
    (bsc#941113,bsc#953971).

  - drm/i915: Fix gen3 self-refresh watermarks
    (bsc#953830,bsc#953971).

  - drm/i915: Fix missing backlight update during panel
    disablement (bsc#941113).

  - drm/i915: Fix SRC_COPY width on 830/845g (bsc#758040).

  - drm/i915: gather backlight information at setup
    (bsc#941113).

  - drm/i915: handle backlight through chip specific
    functions (bsc#941113).

  - drm/i915: Ignore 'digital output' and 'not HDMI output'
    bits for eDP detection (bsc#949192).

  - drm/i915: make asle notifications update backlight on
    all connectors (bsc#941113).

  - drm/i915: make backlight info per-connector
    (bsc#941113).

  - drm/i915: move backlight level setting in enable/disable
    to hooks (bsc#941113).

  - drm/i915: move opregion asle request handling to a work
    queue (bsc#953826).

  - drm/i915: nuke get max backlight functions (bsc#941113).

  - drm/i915/opregion: fix build error on CONFIG_ACPI=n
    (bsc#953826).

  - drm/i915: restore backlight precision when converting
    from ACPI (bsc#941113).

  - drm/i915/tv: add ->get_config callback (bsc#953830).

  - drm/i915: use backlight legacy combination mode also for
    i915gm/i945gm (bsc#941113).

  - drm/i915: use the initialized backlight max value
    instead of reading it (bsc#941113).

  - drm/i915: vlv does not have pipe field in backlight
    registers (bsc#941113).

  - fanotify: fix notification of groups with inode & mount
    marks (bsc#955533).

  - Fix remove_and_add_spares removes drive added as spare
    in slot_store (bsc#956717).

  - genksyms: Handle string literals with spaces in
    reference files (bsc#958510).

  - genksyms: Handle string literals with spaces in
    reference files (bsc#958510).

  - hwrng: Add a driver for the hwrng found in power7+
    systems (fate#315784). in the non-RT kernel to minimize
    the differences.

  - ipv4: Do not increase PMTU with Datagram Too Big message
    (bsc#955224).

  - ipv6: distinguish frag queues by device for multicast
    and link-local packets (bsc#955422).

  - ixgbe: fix broken PFC with X550 (bsc#951864).

  - ixgbe: use correct fcoe ddp max check (bsc#951864).

  - kabi: Fix spurious kabi change in mm/util.c.

  - kABI: protect struct ahci_host_priv.

  - kabi: Restore kabi in struct iscsi_tpg_attrib
    (bsc#954635).

  - kabi: Restore kabi in struct se_cmd (bsc#954635).

  - kabi: Restore kabi in struct se_subsystem_api
    (bsc#954635).

  - ktime: add ktime_after and ktime_before helper
    (bsc#904348).

  - mm: factor commit limit calculation (VM Performance).

  - mm: get rid of 'vmalloc_info' from /proc/meminfo (VM
    Performance).

  - mm: hugetlbfs: skip shared VMAs when unmapping private
    pages to satisfy a fault (Automatic NUMA Balancing
    (fate#315482)).

  - mm: remove PG_waiters from PAGE_FLAGS_CHECK_AT_FREE
    (bnc#943959).

  - mm: vmscan: never isolate more pages than necessary (VM
    Performance).

  - Move ktime_after patch to the networking section

  - nfsrdma: Fix regression in NFSRDMA server (bsc#951110).

  - pci: Drop 'setting latency timer' messages (bsc#956047).

  - pci: Update VPD size with correct length (bsc#924493).

  - perf/x86/intel/uncore: Delete an unnecessary check
    before pci_dev_put() call (bsc#955136).

  - perf/x86/intel/uncore: Delete an unnecessary check
    before pci_dev_put() call (bsc#955136).

  - perf/x86/intel/uncore: Fix multi-segment problem of
    perf_event_intel_uncore (bsc#955136).

  - perf/x86/intel/uncore: Fix multi-segment problem of
    perf_event_intel_uncore (bsc#955136).

  - pm, hinernate: use put_page in release_swap_writer
    (bnc#943959).

  - rcu: Eliminate deadlock between CPU hotplug and
    expedited grace periods (bsc#949706).

  - Re-add copy_page_vector_to_user()

  - ring-buffer: Always run per-cpu ring buffer resize with
    schedule_work_on() (bnc#956711).

  - route: Use ipv4_mtu instead of raw rt_pmtu (bsc#955224).

  - rpm/constraints.in: Require 14GB worth of disk space on
    POWER The builds started to fail randomly due to ENOSPC
    errors.

  - rpm/kernel-binary.spec.in: Always build zImage for ARM

  - rpm/kernel-binary.spec.in: Do not explicitly set
    DEBUG_SECTION_MISMATCH CONFIG_DEBUG_SECTION_MISMATCH is
    a selectable Kconfig option since 2.6.39 and is enabled
    in our configs.

  - rpm/kernel-binary.spec.in: Drop the %build_src_dir macro
    It is the parent directory of the O= directory.

  - rpm/kernel-binary.spec.in: really pass down
    %{?_smp_mflags}

  - rpm/kernel-binary.spec.in: Use parallel make in all
    invocations Also, remove the lengthy comment, since we
    are using a standard rpm macro now.

  - rpm/kernel-binary.spec.in: Use upstream script to
    support config.addon

  - s390/dasd: fix disconnected device with valid path mask
    (bnc#954986, LTC#132707).

  - s390/dasd: fix invalid PAV assignment after
    suspend/resume (bnc#954986, LTC#132706).

  - s390/dasd: fix list_del corruption after lcu changes
    (bnc#954986, LTC#133077).

  - sched: Call select_idle_sibling() when not affine_sd
    (Scheduler Performance).

  - sched/core: Fix task and run queue sched_info::run_delay
    inconsistencies (bnc#949100).

  - sched, isolcpu: make cpu_isolated_map visible outside
    scheduler (bsc#957395).

  - sched/numa: Check all nodes when placing a
    pseudo-interleaved group (Automatic NUMA Balancing
    (fate#315482)).

  - sched/numa: Fix math underflow in task_tick_numa()
    (Automatic NUMA Balancing (fate#315482)).

  - sched/numa: Only consider less busy nodes as numa
    balancing destinations (Automatic NUMA Balancing
    (fate#315482)).

  - sched: Put expensive runtime debugging checks under a
    separate Kconfig entry (Scheduler performance).

  - scsi: hosts: update to use ida_simple for host_no
    (bsc#939926)

  - sunrpc/cache: make cache flushing more reliable
    (bsc#947478).

  - sunrpc: Fix oops when trace sunrpc_task events in nfs
    client (bnc#956703).

  - supported.conf: Support peak_pci and sja1000: These 2
    CAN drivers are supported in the RT kernel for a long
    time so we can also support them

  - target/pr: fix core_scsi3_pr_seq_non_holder() caller
    (bnc#952666).

  - target: Send UA upon LUN RESET tmr completion
    (bsc#933514).

  - target: use 'se_dev_entry' when allocating UAs
    (bsc#933514).

  - Update config files. (bnc#955644)

  - Update kabi files with sbc_parse_cdb symbol change
    (bsc#954635).

  - usbvision fix overflow of interfaces array (bnc#950998).

  - vmxnet3: adjust ring sizes when interface is down
    (bsc#950750).

  - vmxnet3: Fix ethtool -S to return correct rx queue stats
    (bsc#950750).

  - x86/efi: Fix invalid parameter error when getting
    hibernation key (fate#316350, bsc#956284).

  - x86/evtchn: make use of PHYSDEVOP_map_pirq.

  - x86/mm: Add parenthesis for TLB tracepoint size
    calculation (VM Performance (Reduce IPIs during
    reclaim)).

  - x86/mm/hotplug: Modify PGD entry when removing memory
    (VM Functionality, bnc#955148).

  - x86/mm/hotplug: Pass sync_global_pgds() a correct
    argument in remove_pagetable() (VM Functionality,
    bnc#955148).

  - x86/tsc: Let high latency PIT fail fast in
    quick_pit_calibrate() (bsc#953717).

  - xen: fix boot crash in EC2 settings (bsc#956147).

  - xen: refresh patches.xen/xen-x86_64-m2p-strict
    (bsc#956147).

  - xen: Update Xen patches to 3.12.50.

  - xfs: always drain dio before extending aio write
    submission (bsc#949744).

  - xfs: DIO needs an ioend for writes (bsc#949744).

  - xfs: DIO write completion size updates race
    (bsc#949744).

  - xfs: DIO writes within EOF do not need an ioend
    (bsc#949744).

  - xfs: direct IO EOF zeroing needs to drain AIO
    (bsc#949744).

  - xfs: do not allocate an ioend for direct I/O completions
    (bsc#949744).

  - xfs: factor DIO write mapping from get_blocks
    (bsc#949744).

  - xfs: handle DIO overwrite EOF update completion
    correctly (bsc#949744).

  - xfs: move DIO mapping size calculation (bsc#949744).

  - xfs: using generic_file_direct_write() is unnecessary
    (bsc#949744).

  - xhci: Add spurious wakeup quirk for LynxPoint-LP
    controllers (bnc#951165).

  - xhci: Workaround to get Intel xHCI reset working more
    reliably (bnc#957546).

  - zfcp: fix fc_host port_type with NPIV (bnc#954986,
    LTC#132479).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/758040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/814440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/941113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/941202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0272.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2925.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5156.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7799.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7872.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7990.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8215.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152292-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9179e39b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1 :

zypper in -t patch SUSE-SLE-WE-12-SP1-2015-985=1

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2015-985=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2015-985=1

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2015-985=1

SUSE Linux Enterprise Live Patching 12 :

zypper in -t patch SUSE-SLE-Live-Patching-12-2015-985=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2015-985=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/18");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"kernel-default-man-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-debuginfo-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debuginfo-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debugsource-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-devel-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-syms-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-devel-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-syms-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.51-60.20.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
