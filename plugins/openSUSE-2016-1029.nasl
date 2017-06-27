#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1029.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93216);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2014-9904", "CVE-2015-7833", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8845", "CVE-2016-0758", "CVE-2016-1583", "CVE-2016-2053", "CVE-2016-3672", "CVE-2016-4470", "CVE-2016-4482", "CVE-2016-4486", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4805", "CVE-2016-4997", "CVE-2016-4998", "CVE-2016-5244", "CVE-2016-5828", "CVE-2016-5829");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2016-1029)");
  script_summary(english:"Check for the openSUSE-2016-1029 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 13.1 kernel was updated to 3.12.62 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2014-9904: The snd_compress_check_input function in
    sound/core/compress_offload.c in the ALSA subsystem in
    the Linux kernel did not properly check for an integer
    overflow, which allowed local users to cause a denial of
    service (insufficient memory allocation) or possibly
    have unspecified other impact via a crafted
    SNDRV_COMPRESS_SET_PARAMS ioctl call (bnc#986811).

  - CVE-2015-7833: The usbvision driver in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (panic) via a nonzero bInterfaceNumber value
    in a USB device descriptor (bnc#950998).

  - CVE-2015-8551: The PCI backend driver in Xen, when
    running on an x86 system and using Linux 3.1.x through
    4.3.x as the driver domain, allowed local guest
    administrators to hit BUG conditions and cause a denial
    of service (NULL pointer dereference and host OS crash)
    by leveraging a system with access to a passed-through
    MSI or MSI-X capable physical PCI device and a crafted
    sequence of XEN_PCI_OP_* operations, aka 'Linux pciback
    missing sanity checks (bnc#957990).

  - CVE-2015-8552: The PCI backend driver in Xen, when
    running on an x86 system and using Linux 3.1.x through
    4.3.x as the driver domain, allowed local guest
    administrators to generate a continuous stream of WARN
    messages and cause a denial of service (disk
    consumption) by leveraging a system with access to a
    passed-through MSI or MSI-X capable physical PCI device
    and XEN_PCI_OP_enable_msi operations, aka 'Linux pciback
    missing sanity checks (bnc#957990).

  - CVE-2015-8845: The tm_reclaim_thread function in
    arch/powerpc/kernel/process.c in the Linux kernel on
    powerpc platforms did not ensure that TM suspend mode
    exists before proceeding with a tm_reclaim call, which
    allowed local users to cause a denial of service (TM Bad
    Thing exception and panic) via a crafted application
    (bnc#975531 bsc#975533).

  - CVE-2016-0758: Integer overflow in lib/asn1_decoder.c in
    the Linux kernel allowed local users to gain privileges
    via crafted ASN.1 data (bnc#979867).

  - CVE-2016-1583: The ecryptfs_privileged_open function in
    fs/ecryptfs/kthread.c in the Linux kernel allowed local
    users to gain privileges or cause a denial of service
    (stack memory consumption) via vectors involving crafted
    mmap calls for /proc pathnames, leading to recursive
    pagefault handling. (bsc#983143)

  - CVE-2016-2053: The asn1_ber_decoder function in
    lib/asn1_decoder.c in the Linux kernel allowed attackers
    to cause a denial of service (panic) via an ASN.1 BER
    file that lacks a public key, leading to mishandling by
    the public_key_verify_signature function in
    crypto/asymmetric_keys/public_key.c (bnc#963762).

  - CVE-2016-3672: The arch_pick_mmap_layout function in
    arch/x86/mm/mmap.c in the Linux kernel did not properly
    randomize the legacy base address, which made it easier
    for local users to defeat the intended restrictions on
    the ADDR_NO_RANDOMIZE flag, and bypass the ASLR
    protection mechanism for a setuid or setgid program, by
    disabling stack-consumption resource limits
    (bnc#974308).

  - CVE-2016-4470: The key_reject_and_link function in
    security/keys/key.c in the Linux kernel did not ensure
    that a certain data structure is initialized, which
    allowed local users to cause a denial of service (system
    crash) via vectors involving a crafted keyctl request2
    command (bnc#984755).

  - CVE-2016-4482: The proc_connectinfo function in
    drivers/usb/core/devio.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via a crafted USBDEVFS_CONNECTINFO ioctl call.
    (bnc#978401)

  - CVE-2016-4486: The rtnl_fill_link_ifmap function in
    net/core/rtnetlink.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory by reading a Netlink message (bnc#978822).

  - CVE-2016-4565: The InfiniBand (aka IB) stack in the
    Linux kernel incorrectly relies on the write system
    call, which allowed local users to cause a denial of
    service (kernel memory write operation) or possibly have
    unspecified other impact via a uAPI interface
    (bnc#979548 bsc#980363).

  - CVE-2016-4569: The snd_timer_user_params function in
    sound/core/timer.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via crafted use of the ALSA timer interface.
    (bsc#979213)

  - CVE-2016-4578: sound/core/timer.c in the Linux kernel
    did not initialize certain r1 data structures, which
    allowed local users to obtain sensitive information from
    kernel stack memory via crafted use of the ALSA timer
    interface, related to the (1) snd_timer_user_ccallback
    and (2) snd_timer_user_tinterrupt functions
    (bnc#979879).

  - CVE-2016-4805: Use-after-free vulnerability in
    drivers/net/ppp/ppp_generic.c in the Linux kernel
    allowed local users to cause a denial of service (memory
    corruption and system crash, or spinlock) or possibly
    have unspecified other impact by removing a network
    namespace, related to the ppp_register_net_channel and
    ppp_unregister_channel functions (bnc#980371).

  - CVE-2016-4997: The compat IPT_SO_SET_REPLACE setsockopt
    implementation in the netfilter subsystem in the Linux
    kernel allowed local users to gain privileges or cause a
    denial of service (memory corruption) by leveraging
    in-container root access to provide a crafted offset
    value that triggers an unintended decrement
    (bnc#986362).

  - CVE-2016-4998: The IPT_SO_SET_REPLACE setsockopt
    implementation in the netfilter subsystem in the Linux
    kernel before 4.6 allows local users to cause a denial
    of service (out-of-bounds read) or possibly obtain
    sensitive information from kernel heap memory by
    leveraging in-container root access to provide a crafted
    offset value that leads to crossing a ruleset blob
    boundary. (bnc#986365).

  - CVE-2016-5244: The rds_inc_info_copy function in
    net/rds/recv.c in the Linux kernel did not initialize a
    certain structure member, which allowed remote attackers
    to obtain sensitive information from kernel stack memory
    by reading an RDS message (bnc#983213).

  - CVE-2016-5828: The start_thread function in
    arch/powerpc/kernel/process.c in the Linux kernel on
    powerpc platforms mishandled transactional state, which
    allowed local users to cause a denial of service
    (invalid process state or TM Bad Thing exception, and
    system crash) or possibly have unspecified other impact
    by starting and suspending a transaction before an exec
    system call. (bsc#986569)

  - CVE-2016-5829: Multiple heap-based buffer overflows in
    the hiddev_ioctl_usage function in
    drivers/hid/usbhid/hiddev.c in the Linux kernel allow
    local users to cause a denial of service or possibly
    have unspecified other impact via a crafted (1)
    HIDIOCGUSAGES or (2) HIDIOCSUSAGES ioctl call
    (bnc#986572).

The following non-security bugs were fixed :

  - Add wait_event_cmd() (bsc#953048).

  - alsa: hrtimer: Handle start/stop more properly
    (bsc#973378).

  - base: make module_create_drivers_dir race-free
    (bnc#983977).

  - btrfs: be more precise on errors when getting an inode
    from disk (bsc#981038).

  - btrfs: do not use src fd for printk (bsc#980348).

  - btrfs: improve performance on fsync against new inode
    after rename/unlink (bsc#981038).

  - btrfs: qgroup: Fix qgroup accounting when creating
    snapshot (bsc#972933).

  - btrfs: serialize subvolume mounts with potentially
    mismatching rw flags (bsc#951844).

  - cdc_ncm: workaround for EM7455 'silent' data interface
    (bnc#988552).

  - ceph: tolerate bad i_size for symlink inode
    (bsc#985232).

  - drm/mgag200: Add support for a new G200eW3 chipset
    (bsc#983904).

  - drm/mgag200: Add support for a new rev of G200e
    (bsc#983904).

  - drm/mgag200: Black screen fix for G200e rev 4
    (bsc#983904).

  - drm/mgag200: remove unused variables (bsc#983904).

  - drm: qxl: Workaround for buggy user-space (bsc#981344).

  - EDAC: Correct channel count limit (bsc#979521).

  - EDAC: Remove arbitrary limit on number of channels
    (bsc#979521).

  - EDAC, sb_edac: Add support for duplicate device IDs
    (bsc#979521).

  - EDAC/sb_edac: Fix computation of channel address
    (bsc#979521).

  - EDAC, sb_edac: Fix rank lookup on Broadwell
    (bsc#979521).

  - EDAC, sb_edac: Fix TAD presence check for
    sbridge_mci_bind_devs() (bsc#979521).

  - EDAC: Use static attribute groups for managing sysfs
    entries (bsc#979521).

  - efifb: Add support for 64-bit frame buffer addresses
    (bsc#973499).

  - efifb: Fix 16 color palette entry calculation
    (bsc#983318).

  - efifb: Fix KABI of screen_info struct (bsc#973499).

  - ehci-pci: enable interrupt on BayTrail (bnc#947337).

  - enic: set netdev->vlan_features (bsc#966245).

  - fs/cifs: fix wrongly prefixed path to root (bsc#963655,
    bsc#979681)

  - hid-elo: kill not flush the work (bnc#982354).

  - iommu/vt-d: Enable QI on all IOMMUs before setting root
    entry (bsc#975772).

  - ipvs: count pre-established TCP states as active
    (bsc#970114).

  - kabi: prevent spurious modversion changes after
    bsc#982544 fix (bsc#982544).

  - kabi/severities: Added raw3270_* PASS to allow IBM LTC
    changes. (bnc#979922, LTC#141736)

  - ktime: make ktime_divns exported on 32-bit
    architectures.

  - md: be careful when testing resync_max against
    curr_resync_completed (bsc#953048).

  - md: do_release_stripe(): No need to call
    md_wakeup_thread() twice (bsc#953048).

  - md: make sure MD_RECOVERY_DONE is clear before starting
    recovery/resync (bsc#953048).

  - md/raid56: Do not perform reads to support writes until
    stripe is ready.

  - md/raid5: add handle_flags arg to
    break_stripe_batch_list (bsc#953048).

  - md/raid5: allow the stripe_cache to grow and shrink
    (bsc#953048).

  - md/raid5: always set conf->prev_chunk_sectors and
    ->prev_algo (bsc#953048).

  - md/raid5: avoid races when changing cache size
    (bsc#953048).

  - md/raid5: avoid reading parity blocks for full-stripe
    write to degraded array (bsc#953048).

  - md/raid5: be more selective about distributing flags
    across batch (bsc#953048).

  - md/raid5: break stripe-batches when the array has failed
    (bsc#953048).

  - md/raid5: call break_stripe_batch_list from
    handle_stripe_clean_event (bsc#953048).

  - md/raid5: change ->inactive_blocked to a bit-flag
    (bsc#953048).

  - md/raid5: clear R5_NeedReplace when no longer needed
    (bsc#953048).

  - md/raid5: close race between STRIPE_BIT_DELAY and
    batching (bsc#953048).

  - md/raid5: close recently introduced race in stripe_head
    management.

  - md/raid5: consider updating reshape_position at start of
    reshape (bsc#953048).

  - md/raid5: deadlock between retry_aligned_read with
    barrier io (bsc#953048).

  - md/raid5: do not do chunk aligned read on degraded array
    (bsc#953048).

  - md/raid5: do not index beyond end of array in
    need_this_block() (bsc#953048).

  - md/raid5: do not let shrink_slab shrink too far
    (bsc#953048).

  - md/raid5: duplicate some more handle_stripe_clean_event
    code in break_stripe_batch_list (bsc#953048).

  - md/raid5: Ensure a batch member is not handled
    prematurely (bsc#953048).

  - md/raid5: ensure device failure recorded before write
    request returns (bsc#953048).

  - md/raid5: ensure whole batch is delayed for all required
    bitmap updates (bsc#953048).

  - md/raid5: fix allocation of 'scribble' array
    (bsc#953048).

  - md/raid5: fix another livelock caused by non-aligned
    writes (bsc#953048).

  - md/raid5: fix handling of degraded stripes in batches
    (bsc#953048).

  - md/raid5: fix init_stripe() inconsistencies
    (bsc#953048).

  - md/raid5: fix locking in handle_stripe_clean_event()
    (bsc#953048).

  - md/raid5: fix newly-broken locking in get_active_stripe.

  - md/raid5: For stripe with R5_ReadNoMerge, we replace
    REQ_FLUSH with REQ_NOMERGE.

  - md/raid5: handle possible race as reshape completes
    (bsc#953048).

  - md/raid5: ignore released_stripes check (bsc#953048).

  - md/raid5: more incorrect BUG_ON in handle_stripe_fill
    (bsc#953048).

  - md/raid5: move max_nr_stripes management into
    grow_one_stripe and drop_one_stripe (bsc#953048).

  - md/raid5: need_this_block: start simplifying the last
    two conditions (bsc#953048).

  - md/raid5: need_this_block: tidy/fix last condition
    (bsc#953048).

  - md/raid5: new alloc_stripe() to allocate an initialize a
    stripe (bsc#953048).

  - md/raid5: pass gfp_t arg to grow_one_stripe()
    (bsc#953048).

  - md/raid5: per hash value and exclusive wait_for_stripe
    (bsc#953048).

  - md/raid5: preserve STRIPE_PREREAD_ACTIVE in
    break_stripe_batch_list.

  - md/raid5: remove condition test from
    check_break_stripe_batch_list (bsc#953048).

  - md/raid5: remove incorrect 'min_t()' when calculating
    writepos (bsc#953048).

  - md/raid5: remove redundant check in
    stripe_add_to_batch_list() (bsc#953048).

  - md/raid5: separate large if clause out of fetch_block()
    (bsc#953048).

  - md/raid5: separate out the easy conditions in
    need_this_block (bsc#953048).

  - md/raid5: split wait_for_stripe and introduce
    wait_for_quiescent (bsc#953048).

  - md/raid5: strengthen check on reshape_position at run
    (bsc#953048).

  - md/raid5: switch to use conf->chunk_sectors in place of
    mddev->chunk_sectors where possible (bsc#953048).

  - md/raid5: use bio_list for the list of bios to return
    (bsc#953048).

  - md/raid5: use ->lock to protect accessing raid5 sysfs
    attributes (bsc#953048).

  - md: remove unwanted white space from md.c (bsc#953048).

  - md: use set_bit/clear_bit instead of shift/mask for
    bi_flags changes (bsc#953048).

  - mm: increase safety margin provided by PF_LESS_THROTTLE
    (bsc#956491).

  - mm/swap.c: flush lru pvecs on compound page arrival
    (bnc#983721).

  - net: Account for all vlan headers in skb_mac_gso_segment
    (bsc#968667).

  - net: disable fragment reassembly if high_thresh is set
    to zero (bsc#970506).

  - netfilter: bridge: do not leak skb in error paths
    (bsc#982544).

  - netfilter: bridge: forward IPv6 fragmented packets
    (bsc#982544).

  - netfilter: bridge: Use __in6_dev_get rather than
    in6_dev_get in br_validate_ipv6 (bsc#982544).

  - net: fix wrong mac_len calculation for vlans
    (bsc#968667).

  - net/qlge: Avoids recursive EEH error (bsc#954847).

  - net: Start with correct mac_len in skb_network_protocol
    (bsc#968667).

  - nvme: don't poll the CQ from the kthread (bsc#975788,
    bsc#965087).

  - PCI/AER: Clear error status registers during enumeration
    and restore (bsc#985978).

  - perf/rapl: Fix sysfs_show() initialization for RAPL PMU
    (bsc#979489).

  - perf/x86/intel: Add Intel RAPL PP1 energy counter
    support (bsc#979489).

  - ppp: defer netns reference release for ppp channel
    (bsc#980371).

  - qeth: delete napi struct when removing a qeth device
    (bnc#988215, LTC#143590).

  - raid5: add a new flag to track if a stripe can be
    batched (bsc#953048).

  - raid5: add an option to avoid copy data from bio to
    stripe cache (bsc#953048).

  - raid5: avoid release list until last reference of the
    stripe (bsc#953048).

  - raid5: batch adjacent full stripe write (bsc#953048).

  - raid5: check faulty flag for array status during
    recovery (bsc#953048).

  - RAID5: check_reshape() shouldn't call mddev_suspend
    (bsc#953048).

  - raid5: fix a race of stripe count check.

  - raid5: fix broken async operation chain (bsc#953048).

  - raid5: get_active_stripe avoids device_lock.

  - raid5: handle expansion/resync case with stripe batching
    (bsc#953048).

  - raid5: handle io error of batch list (bsc#953048).

  - raid5: make_request does less prepare wait.

  - raid5: relieve lock contention in get_active_stripe().

  - raid5: relieve lock contention in get_active_stripe().

  - raid5: Retry R5_ReadNoMerge flag when hit a read error.

  - RAID5: revert e9e4c377e2f563 to fix a livelock
    (bsc#953048).

  - raid5: speedup sync_request processing (bsc#953048).

  - raid5: track overwrite disk count (bsc#953048).

  - raid5: update analysis state for failed stripe
    (bsc#953048).

  - raid5: use flex_array for scribble data (bsc#953048).

  - Refresh patches.xen/xen-netback-coalesce: Restore
    copying of SKBs with head exceeding page size
    (bsc#978469).

  - s390/3270: add missing tty_kref_put (bnc#979922,
    LTC#141736).

  - s390/3270: avoid endless I/O loop with disconnected 3270
    terminals (bnc#979922, LTC#141736).

  - s390/3270: fix garbled output on 3270 tty view
    (bnc#979922, LTC#141736).

  - s390/3270: fix view reference counting (bnc#979922,
    LTC#141736).

  - s390/3270: handle reconnect of a tty with a different
    size (bnc#979922, LTC#141736).

  - s390/3270: hangup the 3270 tty after a disconnect
    (bnc#979922, LTC#141736).

  - s390: fix test_fp_ctl inline assembly contraints
    (bnc#988215, LTC#143138).

  - s390/mm: fix asce_bits handling with dynamic pagetable
    levels (bnc#979922, LTC#141456).

  - s390/spinlock: avoid yield to non existent cpu
    (bnc#979922, LTC#141106).

  - sb_edac: correctly fetch DIMM width on Ivy Bridge and
    Haswell (bsc#979521).

  - sb_edac: Fix a typo and a thinko in address handling for
    Haswell (bsc#979521).

  - sb_edac: Fix support for systems with two home agents
    per socket (bsc#979521).

  - sb_edac: look harder for DDRIO on Haswell systems
    (bsc#979521).

  - sb_edac: support for Broadwell -EP and -EX (bsc#979521).

  - sched/cputime: Fix clock_nanosleep()/clock_gettime()
    inconsistency (bnc#988498).

  - sched/cputime: Fix cpu_timer_sample_group() double
    accounting (bnc#988498).

  - sched: Provide update_curr callbacks for stop/idle
    scheduling classes (bnc#988498).

  - sched/x86: Fix up typo in topology detection
    (bsc#974165).

  - scsi: Increase REPORT_LUNS timeout (bsc#982282).

  - series.conf: move netfilter section at the end of core
    networking

  - series.conf: move stray netfilter patches to the right
    section

  - target/rbd: do not put snap_context twice (bsc#981143).

  - target/rbd: remove caw_mutex usage (bsc#981143).

  - Update
    patches.drivers/0001-nvme-fix-max_segments-integer-trunc
    ation.patch (bsc#979419). Fix reference.

  - Update
    patches.drivers/nvme-0106-init-nvme-queue-before-enablin
    g-irq.patch (bsc#962742). Fix incorrect bugzilla
    referece.

  - usb: quirk to stop runtime PM for Intel 7260
    (bnc#984456).

  - usb: xhci: Add broken streams quirk for Frescologic
    device id 1009 (bnc#982698).

  - VSOCK: Fix lockdep issue (bsc#977417).

  - VSOCK: sock_put wasn't safe to call in interrupt context
    (bsc#977417).

  - wait: introduce wait_event_exclusive_cmd (bsc#953048).

  - x86 EDAC, sb_edac.c: Repair damage introduced when
    'fixing' channel address (bsc#979521).

  - x86 EDAC, sb_edac.c: Take account of channel hashing
    when needed (bsc#979521).

  - x86/efi: parse_efi_setup() build fix (bsc#979485).

  - x86/mm/pat, /dev/mem: Remove superfluous error message
    (bsc#974620).

  - x86: Removed the free memblock of hibernat keys to avoid
    memory corruption (bsc#990058).

  - x86, sched: Add new topology for multi-NUMA-node CPUs
    (bsc#974165).

  - x86: standardize mmap_rnd() usage (bnc#974308).

  - xen: fix i586 build after SLE12-SP1 commit 2f4c3ff45d5e.

  - xfs: fix premature enospc on inode allocation
    (bsc#984148).

  - xfs: get rid of XFS_IALLOC_BLOCKS macros (bsc#984148).

  - xfs: get rid of XFS_INODE_CLUSTER_SIZE macros
    (bsc#984148)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=947337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973499"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990058"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-eppic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-eppic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-gcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-gcore-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-xen-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipset3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipset3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-controller-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-switch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-switch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-xend-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-xend-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"cloop-2.639-11.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-debuginfo-2.639-11.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-debugsource-2.639-11.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-default-2.639_k3.12.62_52-11.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-default-debuginfo-2.639_k3.12.62_52-11.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-desktop-2.639_k3.12.62_52-11.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-desktop-debuginfo-2.639_k3.12.62_52-11.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-pae-2.639_k3.12.62_52-11.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-pae-debuginfo-2.639_k3.12.62_52-11.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-xen-2.639_k3.12.62_52-11.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-xen-debuginfo-2.639_k3.12.62_52-11.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-7.0.2-2.32.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-debuginfo-7.0.2-2.32.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-debugsource-7.0.2-2.32.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-devel-7.0.2-2.32.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-eppic-7.0.2-2.32.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-eppic-debuginfo-7.0.2-2.32.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-gcore-7.0.2-2.32.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-gcore-debuginfo-7.0.2-2.32.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-default-7.0.2_k3.12.62_52-2.32.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-default-debuginfo-7.0.2_k3.12.62_52-2.32.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-desktop-7.0.2_k3.12.62_52-2.32.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-desktop-debuginfo-7.0.2_k3.12.62_52-2.32.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-pae-7.0.2_k3.12.62_52-2.32.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-pae-debuginfo-7.0.2_k3.12.62_52-2.32.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-xen-7.0.2_k3.12.62_52-2.32.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-xen-debuginfo-7.0.2_k3.12.62_52-2.32.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-debugsource-1.28-16.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-default-1.28_k3.12.62_52-16.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-default-debuginfo-1.28_k3.12.62_52-16.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-desktop-1.28_k3.12.62_52-16.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-desktop-debuginfo-1.28_k3.12.62_52-16.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-pae-1.28_k3.12.62_52-16.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-pae-debuginfo-1.28_k3.12.62_52-16.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-xen-1.28_k3.12.62_52-16.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-xen-debuginfo-1.28_k3.12.62_52-16.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-6.21.1-2.36.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-debuginfo-6.21.1-2.36.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-debugsource-6.21.1-2.36.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-devel-6.21.1-2.36.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-default-6.21.1_k3.12.62_52-2.36.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-default-debuginfo-6.21.1_k3.12.62_52-2.36.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-desktop-6.21.1_k3.12.62_52-2.36.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-desktop-debuginfo-6.21.1_k3.12.62_52-2.36.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-pae-6.21.1_k3.12.62_52-2.36.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-pae-debuginfo-6.21.1_k3.12.62_52-2.36.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-xen-6.21.1_k3.12.62_52-2.36.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-xen-debuginfo-6.21.1_k3.12.62_52-2.36.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-1.4.20.3-13.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-debuginfo-1.4.20.3-13.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-debugsource-1.4.20.3-13.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-default-1.4.20.3_k3.12.62_52-13.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-default-debuginfo-1.4.20.3_k3.12.62_52-13.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-desktop-1.4.20.3_k3.12.62_52-13.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-desktop-debuginfo-1.4.20.3_k3.12.62_52-13.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-pae-1.4.20.3_k3.12.62_52-13.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-pae-debuginfo-1.4.20.3_k3.12.62_52-13.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-xen-1.4.20.3_k3.12.62_52-13.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-xen-debuginfo-1.4.20.3_k3.12.62_52-13.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-base-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-base-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-debugsource-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-devel-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-devel-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-macros-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-source-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-source-vanilla-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-syms-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libipset3-6.21.1-2.36.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libipset3-debuginfo-6.21.1-2.36.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-1.58-33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-debuginfo-1.58-33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-debugsource-1.58-33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-default-1.58_k3.12.62_52-33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-default-debuginfo-1.58_k3.12.62_52-33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-desktop-1.58_k3.12.62_52-33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-desktop-debuginfo-1.58_k3.12.62_52-33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-pae-1.58_k3.12.62_52-33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-pae-debuginfo-1.58_k3.12.62_52-33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-1.11.0-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-controller-1.11.0-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-controller-debuginfo-1.11.0-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-debuginfo-1.11.0-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-debugsource-1.11.0-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-default-1.11.0_k3.12.62_52-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-default-debuginfo-1.11.0_k3.12.62_52-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-desktop-1.11.0_k3.12.62_52-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-desktop-debuginfo-1.11.0_k3.12.62_52-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-pae-1.11.0_k3.12.62_52-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-pae-debuginfo-1.11.0_k3.12.62_52-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-xen-1.11.0_k3.12.62_52-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-xen-debuginfo-1.11.0_k3.12.62_52-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-pki-1.11.0-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-switch-1.11.0-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-switch-debuginfo-1.11.0-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-test-1.11.0-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-0.44-258.33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-debuginfo-0.44-258.33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-debugsource-0.44-258.33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-default-0.44_k3.12.62_52-258.33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-default-debuginfo-0.44_k3.12.62_52-258.33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-desktop-0.44_k3.12.62_52-258.33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-desktop-debuginfo-0.44_k3.12.62_52-258.33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-pae-0.44_k3.12.62_52-258.33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-pae-debuginfo-0.44_k3.12.62_52-258.33.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-openvswitch-1.11.0-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-openvswitch-test-1.11.0-0.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-virtualbox-4.2.36-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-virtualbox-debuginfo-4.2.36-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-debugsource-20130607-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-default-20130607_k3.12.62_52-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-default-debuginfo-20130607_k3.12.62_52-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-desktop-20130607_k3.12.62_52-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-desktop-debuginfo-20130607_k3.12.62_52-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-pae-20130607_k3.12.62_52-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-pae-debuginfo-20130607_k3.12.62_52-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-xen-20130607_k3.12.62_52-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-xen-debuginfo-20130607_k3.12.62_52-2.32.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-4.2.36-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-debuginfo-4.2.36-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-debugsource-4.2.36-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-devel-4.2.36-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-default-4.2.36_k3.12.62_52-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-default-debuginfo-4.2.36_k3.12.62_52-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-desktop-4.2.36_k3.12.62_52-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-desktop-debuginfo-4.2.36_k3.12.62_52-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-pae-4.2.36_k3.12.62_52-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-pae-debuginfo-4.2.36_k3.12.62_52-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-tools-4.2.36-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-tools-debuginfo-4.2.36-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-x11-4.2.36-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-x11-debuginfo-4.2.36-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-default-4.2.36_k3.12.62_52-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-default-debuginfo-4.2.36_k3.12.62_52-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-desktop-4.2.36_k3.12.62_52-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-desktop-debuginfo-4.2.36_k3.12.62_52-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-pae-4.2.36_k3.12.62_52-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-pae-debuginfo-4.2.36_k3.12.62_52-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-source-4.2.36-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-qt-4.2.36-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-qt-debuginfo-4.2.36-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-websrv-4.2.36-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-websrv-debuginfo-4.2.36-2.64.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-debugsource-4.3.4_10-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-devel-4.3.4_10-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-default-4.3.4_10_k3.12.62_52-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-default-debuginfo-4.3.4_10_k3.12.62_52-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-desktop-4.3.4_10_k3.12.62_52-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-desktop-debuginfo-4.3.4_10_k3.12.62_52-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-pae-4.3.4_10_k3.12.62_52-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-pae-debuginfo-4.3.4_10_k3.12.62_52-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-libs-4.3.4_10-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-libs-debuginfo-4.3.4_10-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-tools-domU-4.3.4_10-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-tools-domU-debuginfo-4.3.4_10-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-2.3-2.31.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-debuginfo-2.3-2.31.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-debugsource-2.3-2.31.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-default-2.3_k3.12.62_52-2.31.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-default-debuginfo-2.3_k3.12.62_52-2.31.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-desktop-2.3_k3.12.62_52-2.31.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-desktop-debuginfo-2.3_k3.12.62_52-2.31.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-pae-2.3_k3.12.62_52-2.31.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-pae-debuginfo-2.3_k3.12.62_52-2.31.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-xen-2.3_k3.12.62_52-2.31.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-xen-debuginfo-2.3_k3.12.62_52-2.31.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-base-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-debugsource-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-devel-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-base-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-debugsource-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-devel-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-base-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-debugsource-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-devel-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-base-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-debugsource-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-devel-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-base-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-base-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-debugsource-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-devel-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-debugsource-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-devel-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-base-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-debugsource-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-devel-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-base-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-debugsource-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-devel-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-base-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-devel-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-base-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-devel-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-base-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-debugsource-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-devel-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-base-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-base-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-debugsource-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-devel-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-devel-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-base-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-4.3.4_10-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-doc-html-4.3.4_10-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-libs-32bit-4.3.4_10-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.3.4_10-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-tools-4.3.4_10-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-tools-debuginfo-4.3.4_10-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-xend-tools-4.3.4_10-65.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-xend-tools-debuginfo-4.3.4_10-65.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cloop / cloop-debuginfo / cloop-debugsource / cloop-kmp-default / etc");
}
