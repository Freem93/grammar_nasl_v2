#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-287.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97367);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/03/30 13:31:43 $");

  script_cve_id("CVE-2017-5897", "CVE-2017-5970", "CVE-2017-5986", "CVE-2017-6074");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-287)");
  script_summary(english:"Check for the openSUSE-2017-287 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.1 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2017-6074: The dccp_rcv_state_process function in
    net/dccp/input.c in the Linux kernel mishandled
    DCCP_PKT_REQUEST packet data structures in the LISTEN
    state, which allowed local users to cause a denial of
    service (invalid free) or possibly have unspecified
    other impact via an application that made an
    IPV6_RECVPKTINFO setsockopt system call (bnc#1026024).

  - CVE-2017-5986: Race condition in the
    sctp_wait_for_sndbuf function in net/sctp/socket.c in
    the Linux kernel allowed local users to cause a denial
    of service (assertion failure and panic) via a
    multithreaded application that peels off an association
    in a certain buffer-full state (bnc#1025235).

  - CVE-2017-5970: The ipv4_pktinfo_prepare function in
    net/ipv4/ip_sockglue.c in the Linux kernel allowed
    attackers to cause a denial of service (system crash)
    via (1) an application that made crafted system calls or
    possibly (2) IPv4 traffic with invalid IP options
    (bnc#1024938).

  - CVE-2017-5897: A potential remote denial of service
    within the IPv6 GRE protocol was fixed. (bsc#1023762)

The following non-security bugs were fixed :

  - btrfs: support NFSv2 export (bnc#929871).

  - btrfs: Direct I/O: Fix space accounting (bsc#1025058).

  - btrfs: add RAID 5/6 BTRFS_RBIO_REBUILD_MISSING operation
    (bsc#1025069).

  - btrfs: bail out if block group has different mixed flag
    (bsc#1025072).

  - btrfs: be more precise on errors when getting an inode
    from disk (bsc#981038).

  - btrfs: check pending chunks when shrinking fs to avoid
    corruption (bnc#936445).

  - btrfs: check prepare_uptodate_page() error code earlier
    (bnc#966910).

  - btrfs: do not BUG() during drop snapshot (bsc#1025076).

  - btrfs: do not collect ordered extents when logging that
    inode exists (bsc#977685).

  - btrfs: do not initialize a space info as full to prevent
    ENOSPC (bnc#944001).

  - btrfs: do not leak reloc root nodes on error
    (bsc#1025074).

  - btrfs: fix block group ->space_info NULL pointer
    dereference (bnc#935088).

  - btrfs: fix chunk allocation regression leading to
    transaction abort (bnc#938550).

  - btrfs: fix crash on close_ctree() if cleaner starts new
    transaction (bnc#938891).

  - btrfs: fix deadlock between direct IO reads and buffered
    writes (bsc#973855).

  - btrfs: fix deadlock between direct IO write and
    defrag/readpages (bnc#965344).

  - btrfs: fix device replace of a missing RAID 5/6 device
    (bsc#1025057).

  - btrfs: fix empty symlink after creating symlink and
    fsync parent dir (bsc#977685).

  - btrfs: fix extent accounting for partial direct IO
    writes (bsc#1025062).

  - btrfs: fix file corruption after cloning inline extents
    (bnc#942512).

  - btrfs: fix file loss on log replay after renaming a file
    and fsync (bsc#977685).

  - btrfs: fix file read corruption after extent cloning and
    fsync (bnc#946902).

  - btrfs: fix fitrim discarding device area reserved for
    boot loader's use (bsc#904489).

  - btrfs: fix for incorrect directory entries after fsync
    log replay (bsc#957805, bsc#977685).

  - btrfs: fix hang when failing to submit bio of directIO
    (bnc#942685).

  - btrfs: fix incremental send failure caused by balance
    (bsc#985850).

  - btrfs: fix invalid page accesses in extent_same (dedup)
    ioctl (bnc#968230).

  - btrfs: fix listxattrs not listing all xattrs packed in
    the same item (bsc#1025063).

  - btrfs: fix loading of orphan roots leading to BUG_ON
    (bsc#972844).

  - btrfs: fix memory corruption on failure to submit bio
    for direct IO (bnc#942685).

  - btrfs: fix memory leak in do_walk_down (bsc#1025075).

  - btrfs: fix memory leak in reading btree blocks
    (bsc#1025071).

  - btrfs: fix order by which delayed references are run
    (bnc#949440).

  - btrfs: fix page reading in extent_same ioctl leading to
    csum errors (bnc#968230).

  - btrfs: fix qgroup rescan worker initialization
    (bsc#1025077).

  - btrfs: fix qgroup sanity tests (bnc#951615).

  - btrfs: fix race between balance and unused block group
    deletion (bnc#938892).

  - btrfs: fix race between fsync and lockless direct IO
    writes (bsc#977685).

  - btrfs: fix race waiting for qgroup rescan worker
    (bnc#960300).

  - btrfs: fix regression running delayed references when
    using qgroups (bnc#951615).

  - btrfs: fix regression when running delayed references
    (bnc#951615).

  - btrfs: fix relocation incorrectly dropping data
    references (bsc#990384).

  - btrfs: fix shrinking truncate when the no_holes feature
    is enabled (bsc#1025053).

  - btrfs: fix sleeping inside atomic context in qgroup
    rescan worker (bnc#960300).

  - btrfs: fix stale dir entries after removing a link and
    fsync (bnc#942925).

  - btrfs: fix unreplayable log after snapshot delete +
    parent dir fsync (bsc#977685).

  - btrfs: fix warning in backref walking (bnc#966278).

  - btrfs: fix warning of bytes_may_use (bsc#1025065).

  - btrfs: fix wrong check for btrfs_force_chunk_alloc()
    (bnc#938550).

  - btrfs: handle quota reserve failure properly
    (bsc#1005666).

  - btrfs: incremental send, check if orphanized dir inode
    needs delayed rename (bsc#1025049).

  - btrfs: incremental send, do not delay directory renames
    unnecessarily (bsc#1025048).

  - btrfs: incremental send, fix clone operations for
    compressed extents (fate#316463).

  - btrfs: incremental send, fix premature rmdir operations
    (bsc#1025064).

  - btrfs: keep dropped roots in cache until transaction
    commit (bnc#935087, bnc#945649, bnc#951615).

  - btrfs: remove misleading handling of missing device
    scrub (bsc#1025055).

  - btrfs: remove unnecessary locking of cleaner_mutex to
    avoid deadlock (bsc#904489).

  - btrfs: return gracefully from balance if fs tree is
    corrupted (bsc#1025073).

  - btrfs: send, do not bug on inconsistent snapshots
    (bsc#985850).

  - btrfs: send, fix corner case for reference overwrite
    detection (bsc#1025080).

  - btrfs: send, fix file corruption due to incorrect
    cloning operations (bsc#1025060).

  - btrfs: set UNWRITTEN for prealloc'ed extents in fiemap
    (bsc#1025047).

  - btrfs: test_check_exists: Fix infinite loop when
    searching for free space entries (bsc#987192).

  - btrfs: use btrfs_get_fs_root in resolve_indirect_ref
    (bnc#935087, bnc#945649).

  - btrfs: use received_uuid of parent during send
    (bsc#1025051).

  - btrfs: wake up extent state waiters on unlock through
    clear_extent_bits (bsc#1025050).

  - btrfs: Add handler for invalidate page (bsc#963193).

  - btrfs: Add qgroup tracing (bnc#935087, bnc#945649).

  - btrfs: Avoid truncate tailing page if fallocate range
    does not exceed inode size (bsc#1025059).

  - btrfs: Continue write in case of can_not_nocow
    (bsc#1025070).

  - btrfs: Ensure proper sector alignment for
    btrfs_free_reserved_data_space (bsc#1005666).

  - btrfs: Export and move leaf/subtree qgroup helpers to
    qgroup.c (bsc#983087).

  - btrfs: Fix a data space underflow warning (bsc#985562,
    bsc#975596, bsc#984779).

  - btrfs: Handle unaligned length in extent_same
    (bsc#937609).

  - btrfs: abort transaction on btrfs_reloc_cow_block()
    (bsc#1025081).

  - btrfs: add missing discards when unpinning extents with
    -o discard (bsc#904489).

  - btrfs: advertise which crc32c implementation is being
    used on mount (bsc#946057).

  - btrfs: allow dedupe of same inode (bsc#1025067).

  - btrfs: backref: Add special time_seq == (u64)-1 case for
    btrfs_find_all_roots() (bnc#935087, bnc#945649).

  - btrfs: backref: Do not merge refs which are not for same
    block (bnc#935087, bnc#945649).

  - btrfs: btrfs_issue_discard ensure offset/length are
    aligned to sector boundaries (bsc#904489).

  - btrfs: change max_inline default to 2048 (bsc#949472).

  - btrfs: delayed-ref: Cleanup the unneeded functions
    (bnc#935087, bnc#945649).

  - btrfs: delayed-ref: Use list to replace the ref_root in
    ref_head (bnc#935087, bnc#945649).

  - btrfs: delayed-ref: double free in
    btrfs_add_delayed_tree_ref() (bsc#1025079).

  - btrfs: delayed_ref: Add new function to record reserved
    space into delayed ref (bsc#963193).

  - btrfs: delayed_ref: release and free qgroup reserved at
    proper timing (bsc#963193).

  - btrfs: disable defrag of tree roots.

  - btrfs: do not create or leak aliased root while cleaning
    up orphans (bsc#994881).

  - btrfs: do not update mtime/ctime on deduped inodes
    (bsc#937616).

  - btrfs: explictly delete unused block groups in
    close_ctree and ro-remount (bsc#904489).

  - btrfs: extent-tree: Add new version of
    btrfs_check_data_free_space and
    btrfs_free_reserved_data_space (bsc#963193).

  - btrfs: extent-tree: Add new version of
    btrfs_delalloc_reserve/release_space (bsc#963193).

  - btrfs: extent-tree: Switch to new check_data_free_space
    and free_reserved_data_space (bsc#963193).

  - btrfs: extent-tree: Switch to new delalloc space reserve
    and release (bsc#963193).

  - btrfs: extent-tree: Use ref_node to replace unneeded
    parameters in __inc_extent_ref() and __free_extent()
    (bnc#935087, bnc#945649).

  - btrfs: extent_io: Introduce needed structure for
    recoding set/clear bits (bsc#963193).

  - btrfs: extent_io: Introduce new function
    clear_record_extent_bits() (bsc#963193).

  - btrfs: extent_io: Introduce new function
    set_record_extent_bits (bsc#963193).

  - btrfs: fallocate: Add support to accurate qgroup reserve
    (bsc#963193).

  - btrfs: fix btrfs_compat_ioctl failures on non-compat
    ioctls (bsc#1018100).

  - btrfs: fix clone / extent-same deadlocks (bsc#937612).

  - btrfs: fix deadlock with extent-same and readpage
    (bsc#937612).

  - btrfs: fix resending received snapshot with parent
    (bsc#1025061).

  - btrfs: handle non-fatal errors in btrfs_qgroup_inherit()
    (bsc#972951).

  - btrfs: increment ctx->pos for every emitted or skipped
    dirent in readdir (bsc#981709).

  - btrfs: iterate over unused chunk space in FITRIM
    (bsc#904489).

  - btrfs: make btrfs_issue_discard return bytes discarded
    (bsc#904489).

  - btrfs: make file clone aware of fatal signals
    (bsc#1015787).

  - btrfs: pass unaligned length to btrfs_cmp_data()
    (bsc#937609).

  - btrfs: properly track when rescan worker is running
    (bsc#989953).

  - btrfs: provide super_operations->inode_get_dev
    (bsc#927455).

  - btrfs: qgroup: Add function qgroup_update_counters()
    (bnc#935087, bnc#945649).

  - btrfs: qgroup: Add function qgroup_update_refcnt()
    (bnc#935087, bnc#945649).

  - btrfs: qgroup: Add handler for NOCOW and inline
    (bsc#963193).

  - btrfs: qgroup: Add new function to record old_roots
    (bnc#935087, bnc#945649).

  - btrfs: qgroup: Add new qgroup calculation function
    btrfs_qgroup_account_extents() (bnc#935087, bnc#945649).

  - btrfs: qgroup: Add new trace point for qgroup data
    reserve (bsc#963193).

  - btrfs: qgroup: Add the ability to skip given qgroup for
    old/new_roots (bnc#935087, bnc#945649).

  - btrfs: qgroup: Avoid calling
    btrfs_free_reserved_data_space in clear_bit_hook
    (bsc#963193).

  - btrfs: qgroup: Check if qgroup reserved space leaked
    (bsc#963193).

  - btrfs: qgroup: Cleanup old inaccurate facilities
    (bsc#963193).

  - btrfs: qgroup: Cleanup open-coded old/new_refcnt update
    and read (bnc#935087, bnc#945649).

  - btrfs: qgroup: Cleanup the old ref_node-oriented
    mechanism (bnc#935087, bnc#945649).

  - btrfs: qgroup: Do not copy extent buffer to do qgroup
    rescan (bnc#960300).

  - btrfs: qgroup: Fix a race in delayed_ref which leads to
    abort trans (bsc#963193).

  - btrfs: qgroup: Fix a rebase bug which will cause qgroup
    double free (bsc#963193).

  - btrfs: qgroup: Fix a regression in qgroup reserved space
    (bnc#935087, bnc#945649).

  - btrfs: qgroup: Fix qgroup accounting when creating
    snapshot (bsc#972993).

  - btrfs: qgroup: Fix qgroup data leaking by using subtree
    tracing (bsc#983087).

  - btrfs: qgroup: Introduce btrfs_qgroup_reserve_data
    function (bsc#963193).

  - btrfs: qgroup: Introduce functions to release/free
    qgroup reserve data space (bsc#963193).

  - btrfs: qgroup: Introduce new functions to reserve/free
    metadata (bsc#963193).

  - btrfs: qgroup: Make snapshot accounting work with new
    extent-oriented qgroup (bnc#935087, bnc#945649).

  - btrfs: qgroup: Record possible quota-related extent for
    qgroup (bnc#935087, bnc#945649).

  - btrfs: qgroup: Switch rescan to new mechanism
    (bnc#935087, bnc#945649).

  - btrfs: qgroup: Switch self test to extent-oriented
    qgroup mechanism (bnc#935087, bnc#945649).

  - btrfs: qgroup: Switch to new extent-oriented qgroup
    mechanism (bnc#935087, bnc#945649).

  - btrfs: qgroup: Use new metadata reservation
    (bsc#963193).

  - btrfs: qgroup: account shared subtree during snapshot
    delete (bnc#935087, bnc#945649).

  - btrfs: qgroup: exit the rescan worker during umount
    (bnc#960300).

  - btrfs: qgroup: fix quota disable during rescan
    (bnc#960300).

  - btrfs: remove old tree_root dirent processing in
    btrfs_real_readdir() (bsc#981709).

  - btrfs: serialize subvolume mounts with potentially
    mismatching rw flags (bsc#951844).

  - btrfs: skip superblocks during discard (bsc#904489).

  - btrfs: syslog when quota is disabled.

  - btrfs: syslog when quota is enabled

  - btrfs: ulist: Add ulist_del() function (bnc#935087,
    bnc#945649).

  - btrfs: use the new VFS super_block_dev (bnc#865869).

  - btrfs: waiting on qgroup rescan should not always be
    interruptible (bsc#992712).

  - fs/super.c: add new super block sub devices
    super_block_dev (bnc#865869).

  - fs/super.c: fix race between freeze_super() and
    thaw_super() (bsc#1025066).

  - kabi: only use sops->get_inode_dev with proper fsflag
    (bsc#927455).

  - qgroup: Prevent qgroup->reserved from going subzero
    (bsc#993841).

  - vfs: add super_operations->get_inode_dev (bsc#927455).

  - xfs: do not allow di_size with high bit set
    (bsc#1024234).

  - xfs: exclude never-released buffers from buftarg I/O
    accounting (bsc#1024508).

  - xfs: fix broken multi-fsb buffer logging (bsc#1024081).

  - xfs: fix up xfs_swap_extent_forks inline extent handling
    (bsc#1023888).

  - xfs: track and serialize in-flight async buffers against
    unmount - kABI (bsc#1024508).

  - xfs: track and serialize in-flight async buffers against
    unmount (bsc#1024508)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=865869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=904489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=929871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=935087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=935088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=936445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=938550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=938891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=938892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=942512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=942685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=942925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=944001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=946057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=946902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=992712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994881"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/24");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-base-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-base-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-debugsource-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-devel-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-devel-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-docs-html-4.1.38-50.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-docs-pdf-4.1.38-50.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-macros-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-build-4.1.38-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-build-debugsource-4.1.38-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-qa-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-source-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-source-vanilla-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-syms-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-base-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-base-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-debugsource-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-devel-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-devel-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-base-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-base-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-debugsource-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-devel-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-base-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-base-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-debugsource-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-devel-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-base-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-base-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-debugsource-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-devel-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-debugsource-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-devel-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-base-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-base-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-debugsource-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-devel-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-base-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-debugsource-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-devel-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-base-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-debugsource-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-devel-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-base-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-debugsource-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-devel-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-base-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-base-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-debugsource-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-devel-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-debugsource-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-devel-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-base-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-debuginfo-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-debugsource-4.1.38-50.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-devel-4.1.38-50.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-base-debuginfo / etc");
}
