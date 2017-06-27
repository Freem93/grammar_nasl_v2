#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1696-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93168);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2014-9717", "CVE-2016-1583", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2188", "CVE-2016-2847", "CVE-2016-3134", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3140", "CVE-2016-3689", "CVE-2016-3951", "CVE-2016-4482", "CVE-2016-4486", "CVE-2016-4569");
  script_bugtraq_id(74226);
  script_osvdb_id(121142, 135194, 135678, 135871, 135872, 135873, 135874, 135876, 135878, 135879, 136533, 136805, 137963, 138093, 138383, 139987);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2016:1696-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 SP1 kernel was updated to 3.12.59 to
receive various security and bugfixes.

Main feature additions :

  - Improved support for Clustered File System (CephFS,
    fate#318586).

  - Addition of kGraft patches now produces logging messages
    to simplify auditing (fate#317827).

The following security bugs were fixed :

  - CVE-2016-1583: Prevent the usage of mmap when the lower
    file system does not allow it. This could have lead to
    local privilege escalation when ecryptfs-utils was
    installed and /sbin/mount.ecryptfs_private was setuid
    (bsc#983143).

  - CVE-2014-9717: fs/namespace.c in the Linux kernel
    processes MNT_DETACH umount2 system calls without
    verifying that the MNT_LOCKED flag is unset, which
    allowed local users to bypass intended access
    restrictions and navigate to filesystem locations
    beneath a mount by calling umount2 within a user
    namespace (bnc#928547).

  - CVE-2016-2185: The ati_remote2_probe function in
    drivers/input/misc/ati_remote2.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#971124).

  - CVE-2016-2186: The powermate_probe function in
    drivers/input/misc/powermate.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#970958).

  - CVE-2016-2188: The iowarrior_probe function in
    drivers/usb/misc/iowarrior.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) via
    a crafted endpoints value in a USB device descriptor
    (bnc#970956).

  - CVE-2016-2847: fs/pipe.c in the Linux kernel did not
    limit the amount of unread data in pipes, which allowed
    local users to cause a denial of service (memory
    consumption) by creating many pipes with non-default
    sizes (bsc#970948).

  - CVE-2016-3134: The netfilter subsystem in the Linux
    kernel did not validate certain offset fields, which
    allowed local users to gain privileges or cause a denial
    of service (heap memory corruption) via an
    IPT_SO_SET_REPLACE setsockopt call (bnc#971126 971793).

  - CVE-2016-3136: The mct_u232_msr_to_state function in
    drivers/usb/serial/mct_u232.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted USB device without two interrupt-in
    endpoint descriptors (bnc#970955).

  - CVE-2016-3137: drivers/usb/serial/cypress_m8.c in the
    Linux kernel allowed physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a USB device without both an
    interrupt-in and an interrupt-out endpoint descriptor,
    related to the cypress_generic_port_probe and
    cypress_open functions (bnc#970970).

  - CVE-2016-3138: The acm_probe function in
    drivers/usb/class/cdc-acm.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) via
    a USB device without both a control and a data endpoint
    descriptor (bnc#970911 970970).

  - CVE-2016-3140: The digi_port_init function in
    drivers/usb/serial/digi_acceleport.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#970892).

  - CVE-2016-3689: The ims_pcu_parse_cdc_data function in
    drivers/input/misc/ims-pcu.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (system crash) via a USB device without both a
    master and a slave interface (bnc#971628).

  - CVE-2016-3951: Double free vulnerability in
    drivers/net/usb/cdc_ncm.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (system crash) or possibly have unspecified
    other impact by inserting a USB device with an invalid
    USB descriptor (bnc#974418).

  - CVE-2016-4482: Fixed information leak in devio
    (bnc#978401).

  - CVE-2016-4486: Fixed information leak in rtnetlink (
    bsc#978822).

  - CVE-2016-4569: Fixed information leak in events via
    snd_timer_user_tinterrupt (bsc#979213).

The following non-security bugs were fixed :

  - ALSA: timer: Call notifier in the same spinlock
    (bsc#973378).

  - ALSA: timer: Protect the whole snd_timer_close() with
    open race (bsc#973378).

  - ALSA: timer: Sync timer deletion at closing the system
    timer (bsc#973378).

  - ALSA: timer: Use mod_timer() for rearming the system
    timer (bsc#973378).

  - Btrfs: do not collect ordered extents when logging that
    inode exists (bsc#977685).

  - Btrfs: do not return EBUSY on concurrent subvolume
    mounts (bsc#951844).

  - Btrfs: fix deadlock between direct IO reads and buffered
    writes (bsc#973855).

  - Btrfs: fix empty symlink after creating symlink and
    fsync parent dir (bsc#977685).

  - Btrfs: fix file loss on log replay after renaming a file
    and fsync (bsc#977685).

  - Btrfs: fix file/data loss caused by fsync after rename
    and new inode (bsc#977685).

  - Btrfs: fix for incorrect directory entries after fsync
    log replay (bsc#957805, bsc#977685).

  - Btrfs: fix loading of orphan roots leading to BUG_ON
    (bsc#972844).

  - Btrfs: fix race between fsync and lockless direct IO
    writes (bsc#977685).

  - Btrfs: fix unreplayable log after snapshot delete +
    parent dir fsync (bsc#977685).

  - Btrfs: handle non-fatal errors in btrfs_qgroup_inherit()
    (bsc#972951).

  - Btrfs: qgroup: return EINVAL if level of parent is not
    higher than child's (bsc#972951).

  - Btrfs: teach backref walking about backrefs with
    underflowed offset values (bsc#975371).

  - CacheFiles: Fix incorrect test for in-memory object
    collision (bsc#971049).

  - CacheFiles: Handle object being killed before being set
    up (bsc#971049).

  - Driver: Vmxnet3: set CHECKSUM_UNNECESSARY for IPv6
    packets (bsc#976739).

  - Drivers: hv: util: Pass the channel information during
    the init call (bnc#978527).

  - Drivers: hv: utils: Invoke the poll function after
    handshake (bnc#978527).

  - Drivers: hv: vmbus: Fix signaling logic in
    hv_need_to_signal_on_read().

  - Export helper function to set irq affinity in
    pci-hyperv.

  - FS-Cache: Add missing initialization of ret in
    cachefiles_write_page() (bsc#971049).

  - FS-Cache: Count culled objects and objects rejected due
    to lack of space (bsc#971049).

  - FS-Cache: Fix cancellation of in-progress operation
    (bsc#971049).

  - FS-Cache: Handle a new operation submitted against a
    killed object (bsc#971049).

  - FS-Cache: Move fscache_report_unexpected_submission() to
    make it more available (bsc#971049).

  - FS-Cache: Out of line fscache_operation_init()
    (bsc#971049).

  - FS-Cache: Permit fscache_cancel_op() to cancel
    in-progress operations too (bsc#971049).

  - FS-Cache: Put an aborted initialised op so that it is
    accounted correctly (bsc#971049).

  - FS-Cache: Reduce cookie ref count if submit fails
    (bsc#971049).

  - FS-Cache: Synchronise object death state change vs
    operation submission (bsc#971049).

  - FS-Cache: The operation cancellation method needs
    calling in more places (bsc#971049).

  - FS-Cache: Timeout for releasepage() (bsc#971049).

  - FS-Cache: When submitting an op, cancel it if the target
    object is dying (bsc#971049).

  - FS-Cache: fscache_object_is_dead() has wrong logic, kill
    it (bsc#971049).

  - Fix cifs_uniqueid_to_ino_t() function for s390x
    (bsc#944309)

  - Fix kabi issue (bsc#971049).

  - Input: i8042 - lower log level for 'no controller'
    message (bsc#945345).

  - NFSv4.1: do not use machine credentials for CLOSE when
    using 'sec=sys' (bsc#972003).

  - NVMe: Unify controller probe and resume (bsc#979347).

  - NVMe: init nvme queue before enabling irq (bsc#662458).

  - PCI/AER: Fix aer_inject error codes (bsc#931448).

  - PCI/AER: Log actual error causes in aer_inject
    (bsc#931448).

  - PCI/AER: Log aer_inject error injections (bsc#931448).

  - PCI/AER: Use dev_warn() in aer_inject (bsc#931448).

  - RDMA/ocrdma: Avoid reporting wrong completions in case
    of error CQEs (bsc#908151).

  - Revert 'scsi: fix soft lockup in scsi_remove_target() on
    module removal' (bsc#970609).

  - SUNRPC: Fix large reads on NFS/RDMA (bsc#908151).

  - SUNRPC: remove KERN_INFO from dprintk() call sites
    (bsc#908151).

  - USB: usbip: fix potential out-of-bounds write
    (bnc#975945).

  - Use mainline variant of hyperv KVP IP failover patch
    (bnc#978527)

  - acpi: Disable ACPI table override when UEFI Secure Boot
    is enabled (bsc#970604).

  - acpi: Disable APEI error injection if securelevel is set
    (bsc#972891).

  - apparmor: Skip proc ns files (bsc#959514).

  - cachefiles: perform test on s_blocksize when opening
    cache file (bsc#971049).

  - ceph fscache: Introduce a routine for uncaching single
    no data page from fscache ().

  - ceph fscache: Uncaching no data page from fscache in
    readpage().

  - ceph: Add fs/ceph as a supported module.

  - ceph: Asynchronous IO support.

  - ceph: Avoid to propagate the invalid page point.

  - ceph: Clean up if error occurred in finish_read().

  - ceph: EIO all operations after forced umount.

  - ceph: Implement writev/pwritev for sync operation.

  - ceph: Remove racey watch/notify event infrastructure
    (bsc#964727)

  - ceph: Remove racey watch/notify event infrastructure
    (bsc#964727)

  - ceph: add acl for cephfs.

  - ceph: add acl, noacl options for cephfs mount.

  - ceph: add get_name() NFS export callback.

  - ceph: add get_parent() NFS export callback.

  - ceph: add imported caps when handling cap export
    message.

  - ceph: add inline data to pagecache.

  - ceph: add missing init_acl() for mkdir() and
    atomic_open().

  - ceph: add open export target session helper.

  - ceph: add request to i_unsafe_dirops when getting unsafe
    reply.

  - ceph: additional debugfs output.

  - ceph: always re-send cap flushes when MDS recovers.

  - ceph: avoid block operation when !TASK_RUNNING
    (ceph_get_caps).

  - ceph: avoid block operation when !TASK_RUNNING
    (ceph_mdsc_close_sessions).

  - ceph: avoid block operation when !TASK_RUNNING
    (ceph_mdsc_sync).

  - ceph: avoid releasing caps that are being used.

  - ceph: avoid sending unnessesary FLUSHSNAP message.

  - ceph: avoid useless ceph_get_dentry_parent_inode() in
    ceph_rename().

  - ceph: cast PAGE_SIZE to size_t in ceph_sync_write().

  - ceph: ceph_frag_contains_value can be boolean.

  - ceph: ceph_get_parent() can be static.

  - ceph: check OSD caps before read/write.

  - ceph: check buffer size in ceph_vxattrcb_layout().

  - ceph: check caps in filemap_fault and page_mkwrite.

  - ceph: check directory's completeness before emitting
    directory entry.

  - ceph: check inode caps in ceph_d_revalidate.

  - ceph: check unsupported fallocate mode.

  - ceph: check zero length in ceph_sync_read().

  - ceph: checking for IS_ERR instead of NULL.

  - ceph: cleanup unsafe requests when reconnecting is
    denied.

  - ceph: cleanup use of ceph_msg_get.

  - ceph: clear directory's completeness when creating file.

  - ceph: convert inline data to normal data before data
    write.

  - ceph: do not assume r_old_dentry[_dir] always set
    together.

  - ceph: do not chain inode updates to parent fsync.

  - ceph: do not grabs open file reference for aborted
    request.

  - ceph: do not include ceph.{file,dir}.layout vxattr in
    listxattr().

  - ceph: do not include used caps in cap_wanted.

  - ceph: do not invalidate page cache when inode is no
    longer used.

  - ceph: do not mark dirty caps when there is no auth cap.

  - ceph: do not pre-allocate space for cap release
    messages.

  - ceph: do not set r_old_dentry_dir on link().

  - ceph: do not trim auth cap when there are cap snaps.

  - ceph: do not zero i_wrbuffer_ref when reconnecting is
    denied.

  - ceph: drop cap releases in requests composed before cap
    reconnect.

  - ceph: drop extra open file reference in
    ceph_atomic_open().

  - ceph: drop unconnected inodes.

  - ceph: exclude setfilelock requests when calculating
    oldest tid.

  - ceph: export ceph_session_state_name function.

  - ceph: fetch inline data when getting Fcr cap refs.

  - ceph: fix __dcache_readdir().

  - ceph: fix a comment typo.

  - ceph: fix append mode write.

  - ceph: fix atomic_open snapdir.

  - ceph: fix bool assignments.

  - ceph: fix cache revoke race.

  - ceph: fix ceph_dir_llseek().

  - ceph: fix ceph_fh_to_parent().

  - ceph: fix ceph_removexattr().

  - ceph: fix ceph_set_acl().

  - ceph: fix ceph_writepages_start().

  - ceph: fix dcache/nocache mount option.

  - ceph: fix dentry leaks.

  - ceph: fix directory fsync.

  - ceph: fix divide-by-zero in __validate_layout().

  - ceph: fix double page_unlock() in page_mkwrite().

  - ceph: fix dout() compile warnings in
    ceph_filemap_fault().

  - ceph: fix file lock interruption.

  - ceph: fix flush tid comparision.

  - ceph: fix flushing caps.

  - ceph: fix llistxattr on symlink.

  - ceph: fix message length computation.

  - ceph: fix mksnap crash.

  - ceph: fix NULL pointer dereference in
    send_mds_reconnect().

  - ceph: fix pr_fmt() redefinition.

  - ceph: fix queuing inode to mdsdir's snaprealm.

  - ceph: fix reading inline data when i_size > PAGE_SIZE.

  - ceph: fix request time stamp encoding.

  - ceph: fix reset_readdir().

  - ceph: fix setting empty extended attribute.

  - ceph: fix sizeof(struct tYpO *) typo.

  - ceph: fix snap context leak in error path.

  - ceph: fix trim caps.

  - ceph: fix uninline data function.

  - ceph: flush cap release queue when trimming session
    caps.

  - ceph: flush inline version.

  - ceph: forbid mandatory file lock.

  - ceph: fscache: Update object store limit after file
    writing.

  - ceph: fscache: Wait for completion of object
    initialization.

  - ceph: fscache: add an interface to synchronize object
    store limit.

  - ceph: get inode size for each append write.

  - ceph: handle -ESTALE reply.

  - ceph: handle SESSION_FORCE_RO message.

  - ceph: handle cap export race in try_flush_caps().

  - ceph: handle cap import atomically.

  - ceph: handle frag mismatch between readdir request and
    reply.

  - ceph: handle race between cap reconnect and cap release.

  - ceph: handle session flush message.

  - ceph: hold on to exclusive caps on complete directories.

  - ceph: implement readv/preadv for sync operation.

  - ceph: improve readahead for file holes.

  - ceph: improve reference tracking for snaprealm.

  - ceph: include time stamp in every MDS request.

  - ceph: include time stamp in replayed MDS requests.

  - ceph: initial CEPH_FEATURE_FS_FILE_LAYOUT_V2 support.

  - ceph: initialize inode before instantiating dentry.

  - ceph: introduce a new inode flag indicating if cached
    dentries are ordered.

  - ceph: introduce ceph_fill_fragtree().

  - ceph: introduce global empty snap context.

  - ceph: invalidate dirty pages after forced umount.

  - ceph: keep i_snap_realm while there are writers.

  - ceph: kstrdup() memory handling.

  - ceph: let MDS adjust readdir 'frag'.

  - ceph: make ceph_forget_all_cached_acls() static inline.

  - ceph: make fsync() wait unsafe requests that
    created/modified inode.

  - ceph: make sure syncfs flushes all cap snaps.

  - ceph: make sure write caps are registered with auth MDS.

  - ceph: match wait_for_completion_timeout return type.

  - ceph: message versioning fixes.

  - ceph: move ceph_find_inode() outside the s_mutex.

  - ceph: move spinlocking into ceph_encode_locks_to_buffer
    and ceph_count_locks.

  - ceph: no need to get parent inode in ceph_open.

  - ceph: parse inline data in MClientReply and MClientCaps.

  - ceph: pre-allocate ceph_cap struct for ceph_add_cap().

  - ceph: pre-allocate data structure that tracks caps
    flushing.

  - ceph: preallocate buffer for readdir reply.

  - ceph: print inode number for LOOKUPINO request.

  - ceph: properly apply umask when ACL is enabled.

  - ceph: properly handle XATTR_CREATE and XATTR_REPLACE.

  - ceph: properly mark empty directory as complete.

  - ceph: properly release page upon error.

  - ceph: properly zero data pages for file holes.

  - ceph: provide separate {inode,file}_operations for
    snapdir.

  - ceph: queue cap release in __ceph_remove_cap().

  - ceph: queue vmtruncate if necessary when handing cap
    grant/revoke.

  - ceph: ratelimit warn messages for MDS closes session.

  - ceph: re-send AIO write request when getting -EOLDSNAP
    error.

  - ceph: re-send flushing caps (which are revoked) in
    reconnect stage.

  - ceph: re-send requests when MDS enters reconnecting
    stage.

  - ceph: refactor readpage_nounlock() to make the logic
    clearer.

  - ceph: remember subtree root dirfrag's auth MDS.

  - ceph: remove exported caps when handling cap import
    message.

  - ceph: remove outdated frag information.

  - ceph: remove redundant code for max file size
    verification.

  - ceph: remove redundant declaration.

  - ceph: remove redundant memset(0).

  - ceph: remove redundant test of head->safe and silence
    static analysis warnings.

  - ceph: remove the useless judgement.

  - ceph: remove unused functions in ceph_frag.h.

  - ceph: remove unused stringification macros.

  - ceph: remove useless ACL check.

  - ceph: remove xattr when null value is given to
    setxattr().

  - ceph: rename snapshot support.

  - ceph: replace comma with a semicolon.

  - ceph: request xattrs if xattr_version is zero.

  - ceph: reserve caps for file layout/lock MDS requests.

  - ceph: reset r_resend_mds after receiving -ESTALE.

  - ceph: return error for traceless reply race.

  - ceph: rework dcache readdir.

  - ceph: send TID of the oldest pending caps flush to MDS.

  - ceph: send client metadata to MDS.

  - ceph: set caps count after composing cap reconnect
    message.

  - ceph: set i_head_snapc when getting CEPH_CAP_FILE_WR
    reference.

  - ceph: set mds_wanted when MDS reply changes a cap to
    auth cap.

  - ceph: show nocephx_require_signatures and notcp_nodelay
    options.

  - ceph: show non-default options only.

  - ceph: simplify ceph_fh_to_dentry().

  - ceph: simplify two mount_timeout sites.

  - ceph: skip invalid dentry during dcache readdir.

  - ceph: support inline data feature.

  - ceph: switch some GFP_NOFS memory allocation to
    GFP_KERNEL.

  - ceph: sync read inline data.

  - ceph: take snap_rwsem when accessing snap realm's
    cached_context.

  - ceph: track pending caps flushing accurately.

  - ceph: track pending caps flushing globally.

  - ceph: trim unused inodes before reconnecting to
    recovering MDS.

  - ceph: trivial comment fix.

  - ceph: update i_max_size even if inode version does not
    change.

  - ceph: update inode fields according to issued caps.

  - ceph: use %zu for len in ceph_fill_inline_data().

  - ceph: use ceph_seq_cmp() to compare migrate_seq.

  - ceph: use empty snap context for uninline_data and
    get_pool_perm.

  - ceph: use fl->fl_file as owner identifier of flock and
    posix lock.

  - ceph: use fl->fl_type to decide flock operation.

  - ceph: use fpos_cmp() to compare dentry positions.

  - ceph: use getattr request to fetch inline data.

  - ceph: use i_size_{read,write} to get/set i_size.

  - ceph: use msecs_to_jiffies for time conversion.

  - ceph: use pagelist to present MDS request data.

  - ceph: use truncate_pagecache() instead of
    truncate_inode_pages().

  - ceph_sync_{,direct_}write: fix an oops on
    ceph_osdc_new_request() failure.

  - client: include kernel version in client metadata.

  - cpuset: Fix potential deadlock w/ set_mems_allowed
    (bsc#960857, bsc#974646).

  - crush: add chooseleaf_stable tunable.

  - crush: decode and initialize chooseleaf_stable.

  - crush: ensure bucket id is valid before indexing buckets
    array.

  - crush: ensure take bucket value is valid.

  - crush: fix crash from invalid 'take' argument.

  - crush: sync up with userspace.

  - crypto: testmgr - allow rfc3686 aes-ctr variants in fips
    mode (bsc#958390).

  - crypto: testmgr - mark authenticated ctr(aes) also as
    FIPS able (bsc#958390).

  - dasd: fix hanging system after LCU changes (bnc#968497,
    LTC#136671).

  - drm/core: Preserve the framebuffer after removing it
    (bsc#968812).

  - drm/i915: do not warn if backlight unexpectedly enabled
    (boo#972068).

  - drm/i915: set backlight duty cycle after backlight
    enable for gen4 (boo#972780).

  - drm/radeon: fix-up some float to fixed conversion
    thinkos (bsc#968813).

  - drm/radeon: use HDP_MEM_COHERENCY_FLUSH_CNTL for sdma as
    well (bsc#968813).

  - ext4: Fix softlockups in SEEK_HOLE and SEEK_DATA
    implementations (bsc#942262).

  - ext4: fix races between page faults and hole punching
    (bsc#972174).

  - ext4: fix races of writeback with punch hole and zero
    range (bsc#972174).

  - fs, seq_file: fallback to vmalloc instead of oom kill
    processes (bnc#968687).

  - fs, seqfile: always allow oom killer (bnc#968687).

  - fs/ceph/debugfs.c: replace seq_printf by seq_puts.

  - fs/ceph: replace pr_warning by pr_warn.

  - fs/pipe.c: skip file_update_time on frozen fs
    (bsc#975488).

  - ibmvscsi: Remove unsupported host config MAD
    (bsc#973556).

  - iommu/vt-d: Improve fault handler error messages
    (bsc#975772).

  - iommu/vt-d: Ratelimit fault handler (bsc#975772).

  - ipv6: make fib6 serial number per namespace
    (bsc#965319).

  - ipv6: per netns FIB garbage collection (bsc#965319).

  - ipv6: per netns fib6 walkers (bsc#965319).

  - ipv6: replace global gc_args with local variable
    (bsc#965319).

  - kABI: kgr: fix subtle race with kgr_module_init(), going
    notifier and kgr_modify_kernel().

  - kABI: protect function file_open_root.

  - kABI: protect include in evm.

  - kABI: protect struct user_struct.

  - kabi fix for patches.fixes/reduce-m_start-cost
    (bsc#966573).

  - kabi/severities: Allow changes in zpci_* symbols
    (bsc#974692)

  - kabi/severities: Whitelist libceph and rbd (bsc#964727).

  - kabi: kgr, add reserved fields.

  - kabi: protect struct fc_rport_priv (bsc#953233,
    bsc#962846).

  - kabi: protect struct netns_ipv6 after FIB6 GC series
    (bsc#965319).

  - kgr: add TAINT_KGRAFT.

  - kgr: add kgraft annotation to hwrng kthread.

  - kgr: add kgraft annotations to kthreads'
    wait_event_freezable() API calls.

  - kgr: add objname to kgr_patch_fun struct.

  - kgr: add sympos and objname to error and debug messages.

  - kgr: add sympos as disambiguator field to kgr_patch_fun
    structure.

  - kgr: add sympos to sysfs.

  - kgr: call kgr_init_ftrace_ops() only for loaded objects.

  - kgr: change to kallsyms_on_each_symbol iterator.

  - kgr: define pr_fmt and modify all pr_* messages.

  - kgr: do not print error for !abort_if_missing symbols
    (bnc#943989).

  - kgr: do not return and print an error only if the object
    is not loaded.

  - kgr: do not use WQ_MEM_RECLAIM workqueue (bnc#963572).

  - kgr: fix an asymmetric dealing with delayed module
    loading.

  - kgr: fix redirection on s390x arch (bsc#903279).

  - kgr: fix subtle race with kgr_module_init(), going
    notifier and kgr_modify_kernel().

  - kgr: handle btrfs kthreads (bnc#889207).

  - kgr: kmemleak, really mark the kthread safe after an
    interrupt.

  - kgr: kmemleak, really mark the kthread safe after an
    interrupt.

  - kgr: log when modifying kernel.

  - kgr: mark kernel unsupported upon patch revert.

  - kgr: mark some more missed kthreads (bnc#962336).

  - kgr: remove abort_if_missing flag.

  - kgr: usb/storage: do not emit thread awakened
    (bnc#899908).

  - kgraft/gfs2: Do not block livepatching in the log daemon
    for too long.

  - kgraft/xen: Do not block livepatching in the XEN blkif
    kthread.

  - libceph: Avoid holding the zero page on
    ceph_msgr_slab_init errors.

  - libceph: Fix ceph_tcp_sendpage()'s more boolean usage.

  - libceph: MOSDOpReply v7 encoding.

  - libceph: Remove spurious kunmap() of the zero page.

  - libceph: a couple tweaks for wait loops.

  - libceph: add nocephx_sign_messages option.

  - libceph: advertise support for TUNABLES5.

  - libceph: advertise support for keepalive2.

  - libceph: allow setting osd_req_op's flags.

  - libceph: check data_len in ->alloc_msg().

  - libceph: clear messenger auth_retry flag if we fault.

  - libceph: clear msg->con in ceph_msg_release() only.

  - libceph: do not access invalid memory in keepalive2
    path.

  - libceph: do not spam dmesg with stray reply warnings.

  - libceph: drop authorizer check from cephx msg signing
    routines.

  - libceph: evaluate osd_req_op_data() arguments only once.

  - libceph: fix authorizer invalidation, take 2.

  - libceph: fix ceph_msg_revoke().

  - libceph: fix wrong name 'Ceph filesystem for Linux'.

  - libceph: introduce ceph_x_authorizer_cleanup().

  - libceph: invalidate AUTH in addition to a service
    ticket.

  - libceph: kill off ceph_x_ticket_handler::validity.

  - libceph: move ceph_file_layout helpers to ceph_fs.h.

  - libceph: msg signing callouts do not need con argument.

  - libceph: nuke time_sub().

  - libceph: properly release STAT request's raw_data_in.

  - libceph: remove con argument in handle_reply().

  - libceph: remove outdated comment.

  - libceph: remove the unused macro AES_KEY_SIZE.

  - libceph: rename con_work() to ceph_con_workfn().

  - libceph: set 'exists' flag for newly up osd.

  - libceph: stop duplicating client fields in messenger.

  - libceph: store timeouts in jiffies, verify user input.

  - libceph: treat sockaddr_storage with uninitialized
    family as blank.

  - libceph: use keepalive2 to verify the mon session is
    alive.

  - libceph: use list_for_each_entry_safe.

  - libceph: use list_next_entry instead of list_entry_next.

  - libceph: use local variable cursor instead of
    &msg->cursor.

  - libceph: use the right footer size when skipping a
    message.

  - libfc: replace 'rp_mutex' with 'rp_lock' (bsc#953233,
    bsc#962846).

  - mds: check cap ID when handling cap export message.

  - mmc: Allow forward compatibility for eMMC (bnc#966054).

  - mmc: sdhci: Allow for irq being shared (bnc#977582).

  - mpt3sas: Fix use sas_is_tlr_enabled API before enabling
    MPI2_SCSIIO_CONTROL_TLR_ON flag (bsc#967640).

  - nfs-rdma: Fix for FMR leaks (bsc#908151).

  - nfs: fix high load average due to callback thread
    sleeping (bsc#971170).

  - nvme: fix max_segments integer truncation (bsc#676471).

  - ocfs2: do not set fs read-only if rec[0] is empty while
    committing truncate (bnc#971947).

  - ocfs2: extend enough credits for freeing one truncate
    record while replaying truncate records (bnc#971947).

  - ocfs2: extend transaction for
    ocfs2_remove_rightmost_path() and
    ocfs2_update_edge_lengths() before to avoid
    inconsistency between inode and et (bnc#971947).

  - pipe: limit the per-user amount of pages allocated in
    pipes (bsc#970948).

  - powerpc/book3s64: Fix branching to OOL handlers in
    relocatable kernel (bsc@976821).

  - powerpc/book3s64: Remove __end_handlers marker
    (bsc#976821).

  - rbd: bump queue_max_segments.

  - rbd: delete an unnecessary check before
    rbd_dev_destroy().

  - rbd: do not free rbd_dev outside of the release
    callback.

  - rbd: do not put snap_context twice in
    rbd_queue_workfn().

  - rbd: drop null test before destroy functions.

  - rbd: plug rbd_dev->header.object_prefix memory leak.

  - rbd: rbd_wq comment is obsolete.

  - rbd: remove duplicate calls to rbd_dev_mapping_clear().

  - rbd: return -ENOMEM instead of pool id if
    rbd_dev_create() fails.

  - rbd: set device_type::release instead of
    device::release.

  - rbd: set max_sectors explicitly.

  - rbd: store rbd_options in rbd_device.

  - rbd: terminate rbd_opts_tokens with Opt_err.

  - rbd: timeout watch teardown on unmap with mount_timeout.

  - rbd: use GFP_NOIO consistently for request allocations
    (bsc#971159).

  - rbd: use writefull op for object size writes.

  - reduce m_start() cost.. (bsc#966573).

  - s390/compat: correct restore of high gprs on signal
    return (bnc#968497, LTC#137571).

  - s390/pageattr: do a single TLB flush for
    change_page_attr (bsc#940413).

  - s390/pci: add extra padding to function measurement
    block (bnc#974692, LTC#139445).

  - s390/pci: enforce fmb page boundary rule (bnc#974692,
    LTC#139445).

  - s390/pci: extract software counters from fmb
    (bnc#974692, LTC#139445).

  - s390/pci: remove pdev pointer from arch data
    (bnc#974692, LTC#139444).

  - s390/pci_dma: fix DMA table corruption with > 4 TB main
    memory (bnc#974692, LTC#139401).

  - s390/pci_dma: handle dma table failures (bnc#974692,
    LTC#139442).

  - s390/pci_dma: improve debugging of errors during dma map
    (bnc#974692, LTC#139442).

  - s390/pci_dma: unify label of invalid translation table
    entries (bnc#974692, LTC#139442).

  - s390/zcrypt: HWRNG registration cause kernel panic on
    CEX hotplug (bnc#968497, LTC#138409).

  - scsi-bnx2fc-handle_scsi_retry_delay

  - scsi-bnx2fc-soft_lockup_when_rmmod

  - scsi: Add intermediate STARGET_REMOVE state to
    scsi_target_state (bsc#970609).

  - scsi: Avoid crashing if device uses DIX but adapter does
    not support it (bsc#969016).

  - sd: get disk reference in sd_check_events()
    (bnc#897662).

  - supported.conf: Add bridge.ko for OpenStack (bsc#971600)

  - supported.conf: add pci-hyperv

  - supported.conf:Add
    drivers/infiniband/hw/ocrdma/ocrdma.ko to supported.conf
    (bsc#964461)

  - svcrdma: Fence LOCAL_INV work requests (bsc#908151).

  - svcrdma: advertise the correct max payload (bsc#908151).

  - svcrdma: fix offset calculation for non-page aligned sge
    entries (bsc#908151).

  - svcrdma: fix printk when memory allocation fails
    (bsc#908151).

  - svcrdma: refactor marshalling logic (bsc#908151).

  - svcrdma: send_write() must not overflow the device's max
    sge (bsc#908151).

  - target: Drop incorrect ABORT_TASK put for completed
    commands (bsc#962872).

  - target: Fix LUN_RESET active I/O handling for ACK_KREF
    (bsc#962872).

  - target: Fix LUN_RESET active TMR descriptor handling
    (bsc#962872).

  - target: Fix TAS handling for multi-session se_node_acls
    (bsc#962872).

  - target: Fix race with SCF_SEND_DELAYED_TAS handling
    (bsc#962872).

  - target: Fix remote-port TMR ABORT + se_cmd fabric stop
    (bsc#962872).

  - tcp: convert cached rtt from usec to jiffies when
    feeding initial rto (bsc#937086).

  - vgaarb: Add more context to error messages (bsc#976868).

  - xen/acpi: Disable ACPI table override when UEFI Secure
    Boot is enabled (bsc#970604).

  - xprtrdma: Allocate missing pagelist (bsc#908151).

  - xprtrdma: Avoid deadlock when credit window is reset
    (bsc#908151).

  - xprtrdma: Disconnect on registration failure
    (bsc#908151).

  - xprtrdma: Ensure ia->ri_id->qp is not NULL when
    reconnecting (bsc#908151).

  - xprtrdma: Fall back to MTHCAFMR when FRMR is not
    supported (bsc#908151).

  - xprtrdma: Limit work done by completion handler
    (bsc#908151).

  - xprtrdma: Make rpcrdma_ep_destroy() return void
    (bsc#908151).

  - xprtrdma: RPC/RDMA must invoke xprt_wake_pending_tasks()
    in process context (bsc#908151).

  - xprtrdma: Reduce the number of hardway buffer
    allocations (bsc#908151).

  - xprtrdma: Remove BOUNCEBUFFERS memory registration mode
    (bsc#908151).

  - xprtrdma: Remove BUG_ON() call sites (bsc#908151).

  - xprtrdma: Remove MEMWINDOWS registration modes
    (bsc#908151).

  - xprtrdma: Remove REGISTER memory registration mode
    (bsc#908151).

  - xprtrdma: Remove Tavor MTU setting (bsc#908151).

  - xprtrdma: Reset connection timeout after successful
    reconnect (bsc#908151).

  - xprtrdma: Simplify rpcrdma_deregister_external()
    synopsis (bsc#908151).

  - xprtrdma: Split the completion queue (bsc#908151).

  - xprtrdma: Use macros for reconnection timeout constants
    (bsc#908151).

  - xprtrdma: mind the device's max fast register page list
    depth (bsc#908151).

  - xprtrdma: mount reports 'Invalid mount option' if memreg
    mode not supported (bsc#908151).

  - xprtrmda: Reduce calls to ib_poll_cq() in completion
    handlers (bsc#908151).

  - xprtrmda: Reduce lock contention in completion handlers
    (bsc#908151).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/662458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/676471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/889207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/897662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/899908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/903279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/908151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9717.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1583.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2185.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2186.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2188.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2847.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3134.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3136.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3137.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3138.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3140.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3689.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3951.html"
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
    value:"https://www.suse.com/security/cve/CVE-2016-4569.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161696-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8593c48a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1 :

zypper in -t patch SUSE-SLE-WE-12-SP1-2016-1004=1

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-1004=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-1004=1

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2016-1004=1

SUSE Linux Enterprise Live Patching 12 :

zypper in -t patch SUSE-SLE-Live-Patching-12-2016-1004=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-1004=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
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
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"kernel-default-man-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-debuginfo-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debuginfo-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debugsource-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-devel-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-syms-3.12.59-60.41.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-devel-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-syms-3.12.59-60.41.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.59-60.41.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.59-60.41.2")) flag++;


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
