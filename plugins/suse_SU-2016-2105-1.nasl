#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2105-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93299);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2014-9904", "CVE-2015-7833", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8845", "CVE-2016-0758", "CVE-2016-1583", "CVE-2016-2053", "CVE-2016-3672", "CVE-2016-4470", "CVE-2016-4482", "CVE-2016-4486", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4805", "CVE-2016-4997", "CVE-2016-4998", "CVE-2016-5244", "CVE-2016-5828", "CVE-2016-5829");
  script_osvdb_id(128557, 132030, 132031, 133550, 136761, 137180, 137963, 138093, 138176, 138383, 138431, 138451, 139498, 139987, 140046, 140493, 140494, 140558, 140568, 140680);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2016:2105-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 SP1 kernel was updated to 3.12.62 to
receive various security and bugfixes. The following security bugs
were fixed :

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
    running on an x86 system and using Linux as the driver
    domain, allowed local guest administrators to hit BUG
    conditions and cause a denial of service (NULL pointer
    dereference and host OS crash) by leveraging a system
    with access to a passed-through MSI or MSI-X capable
    physical PCI device and a crafted sequence of
    XEN_PCI_OP_* operations, aka 'Linux pciback missing
    sanity checks (bnc#957990).

  - CVE-2015-8552: The PCI backend driver in Xen, when
    running on an x86 system and using Linux as the driver
    domain, allowed local guest administrators to generate a
    continuous stream of WARN messages and cause a denial of
    service (disk consumption) by leveraging a system with
    access to a passed-through MSI or MSI-X capable physical
    PCI device and XEN_PCI_OP_enable_msi operations, aka
    'Linux pciback missing sanity checks (bnc#957990).

  - CVE-2015-8845: The tm_reclaim_thread function in
    arch/powerpc/kernel/process.c in the Linux kernel on
    powerpc platforms did not ensure that TM suspend mode
    exists before proceeding with a tm_reclaim call, which
    allowed local users to cause a denial of service (TM Bad
    Thing exception and panic) via a crafted application
    (bnc#975533).

  - CVE-2016-0758: Integer overflow in lib/asn1_decoder.c in
    the Linux kernel allowed local users to gain privileges
    via crafted ASN.1 data (bnc#979867).

  - CVE-2016-1583: The ecryptfs_privileged_open function in
    fs/ecryptfs/kthread.c in the Linux kernel allowed local
    users to gain privileges or cause a denial of service
    (stack memory consumption) via vectors involving crafted
    mmap calls for /proc pathnames, leading to recursive
    pagefault handling (bsc#983143).

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
    memory via a crafted USBDEVFS_CONNECTINFO ioctl call
    (bsc#978401).

  - CVE-2016-4486: The rtnl_fill_link_ifmap function in
    net/core/rtnetlink.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory by reading a Netlink message (bnc#978822).

  - CVE-2016-4565: The InfiniBand (aka IB) stack in the
    Linux kernel incorrectly relied on the write system
    call, which allowed local users to cause a denial of
    service (kernel memory write operation) or possibly have
    unspecified other impact via a uAPI interface
    (bnc#979548).

  - CVE-2016-4569: The snd_timer_user_params function in
    sound/core/timer.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via crafted use of the ALSA timer interface
    (bsc#979213).

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
    (bsc#986362).

  - CVE-2016-4998: The IPT_SO_SET_REPLACE setsockopt
    implementation in the netfilter subsystem in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds read) or possibly obtain sensitive
    information from kernel heap memory by leveraging
    in-container root access to provide a crafted offset
    value that leads to crossing a ruleset blob boundary
    (bsc#986365).

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
    by starting and suspending a transaction an exec system
    call (bsc#986569).

  - CVE-2016-5829: Multiple heap-based buffer overflows in
    the hiddev_ioctl_usage function in
    drivers/hid/usbhid/hiddev.c in the Linux kernel allowed
    local users to cause a denial of service or possibly
    have unspecified other impact via a crafted (1)
    HIDIOCGUSAGES or (2) HIDIOCSUSAGES ioctl call
    (bnc#986572). The following non-security bugs were 
fixed :

  - ALSA: hrtimer: Handle start/stop more properly
    (bsc#973378).

  - Add wait_event_cmd() (bsc#953048).

  - Btrfs: be more precise on errors when getting an inode
    from disk (bsc#981038).

  - Btrfs: do not use src fd for printk (bsc#980348).

  - Btrfs: improve performance on fsync against new inode
    after rename/unlink (bsc#981038).

  - Btrfs: qgroup: Fix qgroup accounting when creating
    snapshot (bsc#972933).

  - Btrfs: serialize subvolume mounts with potentially
    mismatching rw flags (bsc#951844).

  - Disable btrfs patch (bsc#981597)

  - EDAC, sb_edac: Add support for duplicate device IDs
    (bsc#979521).

  - EDAC, sb_edac: Fix TAD presence check for
    sbridge_mci_bind_devs() (bsc#979521).

  - EDAC, sb_edac: Fix rank lookup on Broadwell
    (bsc#979521).

  - EDAC/sb_edac: Fix computation of channel address
    (bsc#979521).

  - EDAC: Correct channel count limit (bsc#979521).

  - EDAC: Remove arbitrary limit on number of channels
    (bsc#979521).

  - EDAC: Use static attribute groups for managing sysfs
    entries (bsc#979521).

  - MM: increase safety margin provided by PF_LESS_THROTTLE
    (bsc#956491).

  - PCI/AER: Clear error status registers during enumeration
    and restore (bsc#985978).

  - RAID5: batch adjacent full stripe write (bsc#953048).

  - RAID5: check_reshape() shouldn't call mddev_suspend
    (bsc#953048).

  - RAID5: revert e9e4c377e2f563 to fix a livelock
    (bsc#953048).

  - Restore copying of SKBs with head exceeding page size
    (bsc#978469).

  - SCSI: Increase REPORT_LUNS timeout (bsc#982282).

  - USB: xhci: Add broken streams quirk for Frescologic
    device id 1009 (bnc#982698).

  - Update
    patches.drivers/0001-nvme-fix-max_segments-integer-trunc
    ation.patch (bsc#979419). Fix reference.

  - Update
    patches.drivers/nvme-0106-init-nvme-queue-before-enablin
    g-irq.patch (bsc#962742). Fix incorrect bugzilla
    referece.

  - VSOCK: Fix lockdep issue (bsc#977417).

  - VSOCK: sock_put wasn't safe to call in interrupt context
    (bsc#977417).

  - base: make module_create_drivers_dir race-free
    (bnc#983977).

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

  - kabi/severities: Added raw3270_* PASS to allow IBM LTC
    changes (bnc#979922, LTC#141736)

  - kabi: prevent spurious modversion changes after
    bsc#982544 fix (bsc#982544).

  - kvm: Guest does not show the cpu flag nonstop_tsc
    (bsc#971770)

  - md/raid56: Do not perform reads to support writes until
    stripe is ready.

  - md/raid5: Ensure a batch member is not handled
    prematurely (bsc#953048).

  - md/raid5: For stripe with R5_ReadNoMerge, we replace
    REQ_FLUSH with REQ_NOMERGE.

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

  - md/raid5: use ->lock to protect accessing raid5 sysfs
    attributes (bsc#953048).

  - md/raid5: use bio_list for the list of bios to return
    (bsc#953048).

  - md: be careful when testing resync_max against
    curr_resync_completed (bsc#953048).

  - md: do_release_stripe(): No need to call
    md_wakeup_thread() twice (bsc#953048).

  - md: make sure MD_RECOVERY_DONE is clear before starting
    recovery/resync (bsc#953048).

  - md: remove unwanted white space from md.c (bsc#953048).

  - md: use set_bit/clear_bit instead of shift/mask for
    bi_flags changes (bsc#953048).

  - mm/swap.c: flush lru pvecs on compound page arrival
    (bnc#983721).

  - net/qlge: Avoids recursive EEH error (bsc#954847).

  - net: Account for all vlan headers in skb_mac_gso_segment
    (bsc#968667).

  - net: Start with correct mac_len in skb_network_protocol
    (bsc#968667).

  - net: disable fragment reassembly if high_thresh is set
    to zero (bsc#970506).

  - net: fix wrong mac_len calculation for vlans
    (bsc#968667).

  - netfilter: bridge: Use __in6_dev_get rather than
    in6_dev_get in br_validate_ipv6 (bsc#982544).

  - netfilter: bridge: do not leak skb in error paths
    (bsc#982544).

  - netfilter: bridge: forward IPv6 fragmented packets
    (bsc#982544).

  - nvme: don't poll the CQ from the kthread (bsc#975788,
    bsc#965087).

  - perf/rapl: Fix sysfs_show() initialization for RAPL PMU
    (bsc#979489).

  - perf/x86/intel: Add Intel RAPL PP1 energy counter
    support (bsc#979489).

  - ppp: defer netns reference release for ppp channel
    (bsc#980371).

  - qeth: delete napi struct when removing a qeth device
    (bnc#988215, LTC#143590).

  - raid5: Retry R5_ReadNoMerge flag when hit a read error.

  - raid5: add a new flag to track if a stripe can be
    batched (bsc#953048).

  - raid5: add an option to avoid copy data from bio to
    stripe cache (bsc#953048).

  - raid5: avoid release list until last reference of the
    stripe (bsc#953048).

  - raid5: check faulty flag for array status during
    recovery (bsc#953048).

  - raid5: fix a race of stripe count check.

  - raid5: fix broken async operation chain (bsc#953048).

  - raid5: get_active_stripe avoids device_lock.

  - raid5: handle expansion/resync case with stripe batching
    (bsc#953048).

  - raid5: handle io error of batch list (bsc#953048).

  - raid5: make_request does less prepare wait.

  - raid5: relieve lock contention in get_active_stripe().

  - raid5: relieve lock contention in get_active_stripe().

  - raid5: speedup sync_request processing (bsc#953048).

  - raid5: track overwrite disk count (bsc#953048).

  - raid5: update analysis state for failed stripe
    (bsc#953048).

  - raid5: use flex_array for scribble data (bsc#953048).

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

  - s390/mm: fix asce_bits handling with dynamic pagetable
    levels (bnc#979922, LTC#141456).

  - s390/spinlock: avoid yield to non existent cpu
    (bnc#979922, LTC#141106).

  - s390: fix test_fp_ctl inline assembly contraints
    (bnc#988215, LTC#143138).

  - sb_edac: Fix a typo and a thinko in address handling for
    Haswell (bsc#979521).

  - sb_edac: Fix support for systems with two home agents
    per socket (bsc#979521).

  - sb_edac: correctly fetch DIMM width on Ivy Bridge and
    Haswell (bsc#979521).

  - sb_edac: look harder for DDRIO on Haswell systems
    (bsc#979521).

  - sb_edac: support for Broadwell -EP and -EX (bsc#979521).

  - sched/cputime: Fix clock_nanosleep()/clock_gettime()
    inconsistency (bnc#988498).

  - sched/cputime: Fix cpu_timer_sample_group() double
    accounting (bnc#988498).

  - sched/x86: Fix up typo in topology detection
    (bsc#974165).

  - sched: Provide update_curr callbacks for stop/idle
    scheduling classes (bnc#988498).

  - target/rbd: do not put snap_context twice (bsc#981143).

  - target/rbd: remove caw_mutex usage (bsc#981143).

  - usb: quirk to stop runtime PM for Intel 7260
    (bnc#984456).

  - wait: introduce wait_event_exclusive_cmd (bsc#953048).

  - x86 EDAC, sb_edac.c: Repair damage introduced when
    'fixing' channel address (bsc#979521).

  - x86 EDAC, sb_edac.c: Take account of channel hashing
    when needed (bsc#979521).

  - x86, sched: Add new topology for multi-NUMA-node CPUs
    (bsc#974165).

  - x86/efi: parse_efi_setup() build fix (bsc#979485).

  - x86/mm/pat, /dev/mem: Remove superfluous error message
    (bsc#974620).

  - x86: Removed the free memblock of hibernat keys to avoid
    memory corruption (bsc#990058).

  - x86: standardize mmap_rnd() usage (bnc#974308).

  - xfs: fix premature enospc on inode allocation
    (bsc#984148).

  - xfs: get rid of XFS_IALLOC_BLOCKS macros (bsc#984148).

  - xfs: get rid of XFS_INODE_CLUSTER_SIZE macros
    (bsc#984148).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973499"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/990058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9904.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7833.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8551.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8552.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8845.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0758.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1583.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2053.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3672.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4470.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4482.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4486.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4565.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4578.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4997.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4998.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5244.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5828.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5829.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162105-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b0479a5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1:zypper in -t patch
SUSE-SLE-WE-12-SP1-2016-1246=1

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1246=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1246=1

SUSE Linux Enterprise Module for Public Cloud 12:zypper in -t patch
SUSE-SLE-Module-Public-Cloud-12-2016-1246=1

SUSE Linux Enterprise Live Patching 12:zypper in -t patch
SUSE-SLE-Live-Patching-12-2016-1246=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1246=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:X/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"kernel-default-man-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-debuginfo-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debuginfo-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debugsource-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-devel-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-syms-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-devel-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-syms-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.62-60.62.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.62-60.62.1")) flag++;


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
