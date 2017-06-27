#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-862.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(92007);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2014-9717", "CVE-2015-8539", "CVE-2015-8816", "CVE-2016-1583", "CVE-2016-2143", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2188", "CVE-2016-2782", "CVE-2016-2847", "CVE-2016-3134", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-3689", "CVE-2016-3951", "CVE-2016-4482", "CVE-2016-4486", "CVE-2016-4569", "CVE-2016-4997");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2016-862)");
  script_summary(english:"Check for the openSUSE-2016-862 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"======================================================================
The openSUSE 13.1 kernel was updated to 3.12.59 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2016-4997: A buffer overflow in 32bit
    compat_setsockopt iptables handling could lead to a
    local privilege escalation. (bsc#986362)

  - CVE-2014-9717: fs/namespace.c in the Linux kernel
    processes MNT_DETACH umount2 system calls without
    verifying that the MNT_LOCKED flag is unset, which
    allowed local users to bypass intended access
    restrictions and navigate to filesystem locations
    beneath a mount by calling umount2 within a user
    namespace (bnc#928547).

  - CVE-2015-8539: The KEYS subsystem in the Linux kernel
    allowed local users to gain privileges or cause a denial
    of service (BUG) via crafted keyctl commands that
    negatively instantiate a key, related to
    security/keys/encrypted-keys/encrypted.c,
    security/keys/trusted.c, and
    security/keys/user_defined.c (bnc#958463).

  - CVE-2015-8816: The hub_activate function in
    drivers/usb/core/hub.c in the Linux kernel did not
    properly maintain a hub-interface data structure, which
    allowed physically proximate attackers to cause a denial
    of service (invalid memory access and system crash) or
    possibly have unspecified other impact by unplugging a
    USB hub device (bnc#968010 979064).

  - CVE-2016-1583: The ecryptfs_privileged_open function in
    fs/ecryptfs/kthread.c in the Linux kernel allowed local
    users to gain privileges or cause a denial of service
    (stack memory consumption) via vectors involving crafted
    mmap calls for /proc pathnames, leading to recursive
    pagefault handling (bnc#983143).

  - CVE-2016-2143: The fork implementation in the Linux
    kernel on s390 platforms mishandled the case of four
    page-table levels, which allowed local users to cause a
    denial of service (system crash) or possibly have
    unspecified other impact via a crafted application,
    related to arch/s390/include/asm/mmu_context.h and
    arch/s390/include/asm/pgalloc.h (bnc#970504).

  - CVE-2016-2184: The create_fixed_stream_quirk function in
    sound/usb/quirks.c in the snd-usb-audio driver in the
    Linux kernel allowed physically proximate attackers to
    cause a denial of service (NULL pointer dereference or
    double free, and system crash) via a crafted endpoints
    value in a USB device descriptor (bnc#971125).

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

  - CVE-2016-2782: The treo_attach function in
    drivers/usb/serial/visor.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) or
    possibly have unspecified other impact by inserting a
    USB device that lacks a (1) bulk-in or (2) interrupt-in
    endpoint (bnc#961512 968670).

  - CVE-2016-2847: fs/pipe.c in the Linux kernel did not
    limit the amount of unread data in pipes, which allowed
    local users to cause a denial of service (memory
    consumption) by creating many pipes with non-default
    sizes (bnc#970948 bnc#974646).

  - CVE-2016-3134: The netfilter subsystem in the Linux
    kernel did not validate certain offset fields, which
    allowed local users to gain privileges or cause a denial
    of service (heap memory corruption) via an
    IPT_SO_SET_REPLACE setsockopt call (bnc#971126).

  - CVE-2016-3136: The mct_u232_msr_to_state function in
    drivers/usb/serial/mct_u232.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted USB device without two interrupt-in
    endpoint descriptors (bnc#970955).

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

  - CVE-2016-3156: The IPv4 implementation in the Linux
    kernel mishandled destruction of device objects, which
    allowed guest OS users to cause a denial of service
    (host OS networking outage) by arranging for a large
    number of IP addresses (bnc#971360).

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

  - CVE-2016-4482: The proc_connectinfo function in
    drivers/usb/core/devio.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via a crafted USBDEVFS_CONNECTINFO ioctl call
    (bnc#978401 bsc#978445).

  - CVE-2016-4486: The rtnl_fill_link_ifmap function in
    net/core/rtnetlink.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory by reading a Netlink message (bnc#978822).

  - CVE-2016-4569: The snd_timer_user_params function in
    sound/core/timer.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via crafted use of the ALSA timer interface
    (bnc#979213).

The following non-security bugs were fixed :

  - ALSA: timer: Call notifier in the same spinlock
    (bsc#973378).

  - ALSA: timer: Protect the whole snd_timer_close() with
    open race (bsc#973378).

  - ALSA: timer: Sync timer deletion at closing the system
    timer (bsc#973378).

  - ALSA: timer: Use mod_timer() for rearming the system
    timer (bsc#973378).

  - Add fs/ceph as a supported module.

  - Add mainline tags to some hyperv patches

  - Btrfs: do not collect ordered extents when logging that
    inode exists (bsc#977685).

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

  - Btrfs: teach backref walking about backrefs with
    underflowed offset values (bsc#975371).

  - CacheFiles: Fix incorrect test for in-memory object
    collision (bsc#971049).

  - CacheFiles: Handle object being killed before being set
    up (bsc#971049).

  - Ceph: Remove racey watch/notify event infrastructure
    (bsc#964727)

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

  - Import kabi files from kernel 3.12.55-52.42

  - Import kabi files from kernel 3.12.57-60.35

  - Input: i8042 - lower log level for 'no controller'
    message (bsc#945345).

  - KVM: x86: expose invariant tsc cpuid bit (v2)
    (bsc#971770).

  - NFSv4.1: do not use machine credentials for CLOSE when
    using 'sec=sys' (bsc#972003).

  - NVMe: Unify controller probe and resume (bsc#979347).

  - NVMe: init nvme queue before enabling irq (unknown bsc).

  - PCI/AER: Fix aer_inject error codes (bsc#931448).

  - PCI/AER: Log actual error causes in aer_inject
    (bsc#931448).

  - PCI/AER: Log aer_inject error injections (bsc#931448).

  - PCI/AER: Use dev_warn() in aer_inject (bsc#931448).

  - RDMA/ocrdma: Avoid reporting wrong completions in case
    of error CQEs (bsc#908151).

  - Remove VIOSRP_HOST_CONFIG_TYPE from ibmvstgt.c in
    patches.fixes/0001-ibmvscsi-remove-unsupported-host-conf
    ig-mad.patch. as well.

  - Revert 'scsi: fix soft lockup in scsi_remove_target() on
    module removal' (bsc#970609).

  - SUNRPC: Fix large reads on NFS/RDMA (bsc#908151).

  - SUNRPC: remove KERN_INFO from dprintk() call sites
    (bsc#908151).

  - USB: usbip: fix potential out-of-bounds write
    (bnc#975945).

  - Update patches.kernel.org/patch-3.12.55-56 references
    (add bsc#973570).

  - Update patches.suse/kgr-0102-add-TAINT_KGRAFT.patch
    (fate#313296 bsc#974406).

  - Use mainline variant of hyperv KVP IP failover patch
    (bnc#978527)

  - acpi: Disable ACPI table override when UEFI Secure Boot
    is enabled (bsc#970604).

  - acpi: Disable APEI error injection if securelevel is set
    (bsc#972891).

  - apparmor: Skip proc ns files (bsc#959514).

  - block: do not check request size in
    blk_cloned_rq_check_limits() (bsc#972124).

  -
    bnx2fc-Do-not-log-for-netevents-that-need-no-action.patc
    h

  - btrfs: do not return EBUSY on concurrent subvolume
    mounts (bsc#951844).

  - btrfs: handle non-fatal errors in btrfs_qgroup_inherit()
    (bsc#972951).

  - btrfs: qgroup: return EINVAL if level of parent is not
    higher than child's (bsc#972951).

  - cachefiles: perform test on s_blocksize when opening
    cache file (bsc#971049).

  - ceph fscache: Introduce a routine for uncaching single
    no data page from fscache (Fate#318586).

  - ceph fscache: Uncaching no data page from fscache in
    readpage() (Fate#318586).

  - ceph: Asynchronous IO support (Fate#318586).

  - ceph: Avoid to propagate the invalid page point
    (Fate#318586).

  - ceph: Clean up if error occurred in finish_read()
    (Fate#318586).

  - ceph: EIO all operations after forced umount
    (Fate#318586).

  - ceph: Implement writev/pwritev for sync operation
    (Fate#318586).

  - ceph: add acl for cephfs (Fate#318586).

  - ceph: add acl, noacl options for cephfs mount
    (Fate#318586).

  - ceph: add get_name() NFS export callback (Fate#318586).

  - ceph: add get_parent() NFS export callback
    (Fate#318586).

  - ceph: add imported caps when handling cap export message
    (Fate#318586).

  - ceph: add inline data to pagecache (Fate#318586).

  - ceph: add missing init_acl() for mkdir() and
    atomic_open() (Fate#318586).

  - ceph: add open export target session helper
    (Fate#318586).

  - ceph: add request to i_unsafe_dirops when getting unsafe
    reply (Fate#318586).

  - ceph: additional debugfs output (Fate#318586).

  - ceph: always re-send cap flushes when MDS recovers
    (Fate#318586).

  - ceph: avoid block operation when !TASK_RUNNING
    (ceph_mdsc_close_sessions) (Fate#318586).

  - ceph: avoid block operation when !TASK_RUNNING
    (ceph_get_caps) (Fate#318586).

  - ceph: avoid block operation when !TASK_RUNNING
    (ceph_mdsc_sync) (Fate#318586).

  - ceph: avoid releasing caps that are being used
    (Fate#318586).

  - ceph: avoid sending unnessesary FLUSHSNAP message
    (Fate#318586).

  - ceph: avoid useless ceph_get_dentry_parent_inode() in
    ceph_rename() (Fate#318586).

  - ceph: cast PAGE_SIZE to size_t in ceph_sync_write()
    (Fate#318586).

  - ceph: ceph_frag_contains_value can be boolean
    (Fate#318586).

  - ceph: ceph_get_parent() can be static (Fate#318586).

  - ceph: check OSD caps before read/write (Fate#318586).

  - ceph: check buffer size in ceph_vxattrcb_layout()
    (Fate#318586).

  - ceph: check caps in filemap_fault and page_mkwrite
    (Fate#318586).

  - ceph: check directory's completeness before emitting
    directory entry (Fate#318586).

  - ceph: check inode caps in ceph_d_revalidate
    (Fate#318586).

  - ceph: check unsupported fallocate mode (Fate#318586).

  - ceph: check zero length in ceph_sync_read()
    (Fate#318586).

  - ceph: checking for IS_ERR instead of NULL (Fate#318586).

  - ceph: cleanup unsafe requests when reconnecting is
    denied (Fate#318586).

  - ceph: cleanup use of ceph_msg_get (Fate#318586).

  - ceph: clear directory's completeness when creating file
    (Fate#318586).

  - ceph: convert inline data to normal data before data
    write (Fate#318586).

  - ceph: do not assume r_old_dentry[_dir] always set
    together (Fate#318586).

  - ceph: do not chain inode updates to parent fsync
    (Fate#318586).

  - ceph: do not grabs open file reference for aborted
    request (Fate#318586).

  - ceph: do not include ceph.{file,dir}.layout vxattr in
    listxattr() (Fate#318586).

  - ceph: do not include used caps in cap_wanted
    (Fate#318586).

  - ceph: do not invalidate page cache when inode is no
    longer used (Fate#318586).

  - ceph: do not mark dirty caps when there is no auth cap
    (Fate#318586).

  - ceph: do not pre-allocate space for cap release messages
    (Fate#318586).

  - ceph: do not set r_old_dentry_dir on link()
    (Fate#318586).

  - ceph: do not trim auth cap when there are cap snaps
    (Fate#318586).

  - ceph: do not zero i_wrbuffer_ref when reconnecting is
    denied (Fate#318586).

  - ceph: drop cap releases in requests composed before cap
    reconnect (Fate#318586).

  - ceph: drop extra open file reference in
    ceph_atomic_open() (Fate#318586).

  - ceph: drop unconnected inodes (Fate#318586).

  - ceph: exclude setfilelock requests when calculating
    oldest tid (Fate#318586).

  - ceph: export ceph_session_state_name function
    (Fate#318586).

  - ceph: fetch inline data when getting Fcr cap refs
    (Fate#318586).

  - ceph: fix __dcache_readdir() (Fate#318586).

  - ceph: fix a comment typo (Fate#318586).

  - ceph: fix append mode write (Fate#318586).

  - ceph: fix atomic_open snapdir (Fate#318586).

  - ceph: fix bool assignments (Fate#318586).

  - ceph: fix cache revoke race (Fate#318586).

  - ceph: fix ceph_dir_llseek() (Fate#318586).

  - ceph: fix ceph_fh_to_parent() (Fate#318586).

  - ceph: fix ceph_removexattr() (Fate#318586).

  - ceph: fix ceph_set_acl() (Fate#318586).

  - ceph: fix ceph_writepages_start() (Fate#318586).

  - ceph: fix dcache/nocache mount option (Fate#318586).

  - ceph: fix dentry leaks (Fate#318586).

  - ceph: fix directory fsync (Fate#318586).

  - ceph: fix divide-by-zero in __validate_layout()
    (Fate#318586).

  - ceph: fix double page_unlock() in page_mkwrite()
    (Fate#318586).

  - ceph: fix dout() compile warnings in
    ceph_filemap_fault() (Fate#318586).

  - ceph: fix file lock interruption (Fate#318586).

  - ceph: fix flush tid comparision (Fate#318586).

  - ceph: fix flushing caps (Fate#318586).

  - ceph: fix llistxattr on symlink (Fate#318586).

  - ceph: fix message length computation (Fate#318586).

  - ceph: fix mksnap crash (Fate#318586).

  - ceph: fix NULL pointer dereference in
    send_mds_reconnect() (Fate#318586).

  - ceph: fix pr_fmt() redefinition (Fate#318586).

  - ceph: fix queuing inode to mdsdir's snaprealm
    (Fate#318586).

  - ceph: fix reading inline data when i_size > PAGE_SIZE
    (Fate#318586).

  - ceph: fix request time stamp encoding (Fate#318586).

  - ceph: fix reset_readdir() (Fate#318586).

  - ceph: fix setting empty extended attribute
    (Fate#318586).

  - ceph: fix sizeof(struct tYpO *) typo (Fate#318586).

  - ceph: fix snap context leak in error path (Fate#318586).

  - ceph: fix trim caps (Fate#318586).

  - ceph: fix uninline data function (Fate#318586).

  - ceph: flush cap release queue when trimming session caps
    (Fate#318586).

  - ceph: flush inline version (Fate#318586).

  - ceph: forbid mandatory file lock (Fate#318586).

  - ceph: fscache: Update object store limit after file
    writing (Fate#318586).

  - ceph: fscache: Wait for completion of object
    initialization (Fate#318586).

  - ceph: fscache: add an interface to synchronize object
    store limit (Fate#318586).

  - ceph: get inode size for each append write
    (Fate#318586).

  - ceph: handle -ESTALE reply (Fate#318586).

  - ceph: handle SESSION_FORCE_RO message (Fate#318586).

  - ceph: handle cap export race in try_flush_caps()
    (Fate#318586).

  - ceph: handle cap import atomically (Fate#318586).

  - ceph: handle frag mismatch between readdir request and
    reply (Fate#318586).

  - ceph: handle race between cap reconnect and cap release
    (Fate#318586).

  - ceph: handle session flush message (Fate#318586).

  - ceph: hold on to exclusive caps on complete directories
    (Fate#318586).

  - ceph: implement readv/preadv for sync operation
    (Fate#318586).

  - ceph: improve readahead for file holes (Fate#318586).

  - ceph: improve reference tracking for snaprealm
    (Fate#318586).

  - ceph: include time stamp in every MDS request
    (Fate#318586).

  - ceph: include time stamp in replayed MDS requests
    (Fate#318586).

  - ceph: initial CEPH_FEATURE_FS_FILE_LAYOUT_V2 support
    (Fate#318586).

  - ceph: initialize inode before instantiating dentry
    (Fate#318586).

  - ceph: introduce a new inode flag indicating if cached
    dentries are ordered (Fate#318586).

  - ceph: introduce ceph_fill_fragtree() (Fate#318586).

  - ceph: introduce global empty snap context (Fate#318586).

  - ceph: invalidate dirty pages after forced umount
    (Fate#318586).

  - ceph: keep i_snap_realm while there are writers
    (Fate#318586).

  - ceph: kstrdup() memory handling (Fate#318586).

  - ceph: let MDS adjust readdir 'frag' (Fate#318586).

  - ceph: make ceph_forget_all_cached_acls() static inline
    (Fate#318586).

  - ceph: make fsync() wait unsafe requests that
    created/modified inode (Fate#318586).

  - ceph: make sure syncfs flushes all cap snaps
    (Fate#318586).

  - ceph: make sure write caps are registered with auth MDS
    (Fate#318586).

  - ceph: match wait_for_completion_timeout return type
    (Fate#318586).

  - ceph: message versioning fixes (Fate#318586).

  - ceph: move ceph_find_inode() outside the s_mutex
    (Fate#318586).

  - ceph: move spinlocking into ceph_encode_locks_to_buffer
    and ceph_count_locks (Fate#318586).

  - ceph: no need to get parent inode in ceph_open
    (Fate#318586).

  - ceph: parse inline data in MClientReply and MClientCaps
    (Fate#318586).

  - ceph: pre-allocate ceph_cap struct for ceph_add_cap()
    (Fate#318586).

  - ceph: pre-allocate data structure that tracks caps
    flushing (Fate#318586).

  - ceph: preallocate buffer for readdir reply
    (Fate#318586).

  - ceph: print inode number for LOOKUPINO request
    (Fate#318586).

  - ceph: properly apply umask when ACL is enabled
    (Fate#318586).

  - ceph: properly handle XATTR_CREATE and XATTR_REPLACE
    (Fate#318586).

  - ceph: properly mark empty directory as complete
    (Fate#318586).

  - ceph: properly release page upon error (Fate#318586).

  - ceph: properly zero data pages for file holes
    (Fate#318586).

  - ceph: provide separate {inode,file}_operations for
    snapdir (Fate#318586).

  - ceph: queue cap release in __ceph_remove_cap()
    (Fate#318586).

  - ceph: queue vmtruncate if necessary when handing cap
    grant/revoke (Fate#318586).

  - ceph: ratelimit warn messages for MDS closes session
    (Fate#318586).

  - ceph: re-send AIO write request when getting -EOLDSNAP
    error (Fate#318586).

  - ceph: re-send flushing caps (which are revoked) in
    reconnect stage (Fate#318586).

  - ceph: re-send requests when MDS enters reconnecting
    stage (Fate#318586).

  - ceph: refactor readpage_nounlock() to make the logic
    clearer (Fate#318586).

  - ceph: remember subtree root dirfrag's auth MDS
    (Fate#318586).

  - ceph: remove exported caps when handling cap import
    message (Fate#318586).

  - ceph: remove outdated frag information (Fate#318586).

  - ceph: remove redundant code for max file size
    verification (Fate#318586).

  - ceph: remove redundant declaration (Fate#318586).

  - ceph: remove redundant memset(0) (Fate#318586).

  - ceph: remove redundant test of head->safe and silence
    static analysis warnings (Fate#318586).

  - ceph: remove the useless judgement (Fate#318586).

  - ceph: remove unused functions in ceph_frag.h
    (Fate#318586).

  - ceph: remove unused stringification macros
    (Fate#318586).

  - ceph: remove useless ACL check (Fate#318586).

  - ceph: remove xattr when null value is given to
    setxattr() (Fate#318586).

  - ceph: rename snapshot support (Fate#318586).

  - ceph: replace comma with a semicolon (Fate#318586).

  - ceph: request xattrs if xattr_version is zero
    (Fate#318586).

  - ceph: reserve caps for file layout/lock MDS requests
    (Fate#318586).

  - ceph: reset r_resend_mds after receiving -ESTALE
    (Fate#318586).

  - ceph: return error for traceless reply race
    (Fate#318586).

  - ceph: rework dcache readdir (Fate#318586).

  - ceph: send TID of the oldest pending caps flush to MDS
    (Fate#318586).

  - ceph: send client metadata to MDS (Fate#318586).

  - ceph: set caps count after composing cap reconnect
    message (Fate#318586).

  - ceph: set i_head_snapc when getting CEPH_CAP_FILE_WR
    reference (Fate#318586).

  - ceph: set mds_wanted when MDS reply changes a cap to
    auth cap (Fate#318586).

  - ceph: show nocephx_require_signatures and notcp_nodelay
    options (Fate#318586).

  - ceph: show non-default options only (Fate#318586).

  - ceph: simplify ceph_fh_to_dentry() (Fate#318586).

  - ceph: simplify two mount_timeout sites (Fate#318586).

  - ceph: skip invalid dentry during dcache readdir
    (Fate#318586).

  - ceph: support inline data feature (Fate#318586).

  - ceph: switch some GFP_NOFS memory allocation to
    GFP_KERNEL (Fate#318586).

  - ceph: sync read inline data (Fate#318586).

  - ceph: take snap_rwsem when accessing snap realm's
    cached_context (Fate#318586).

  - ceph: track pending caps flushing accurately
    (Fate#318586).

  - ceph: track pending caps flushing globally
    (Fate#318586).

  - ceph: trim unused inodes before reconnecting to
    recovering MDS (Fate#318586).

  - ceph: trivial comment fix (Fate#318586).

  - ceph: update i_max_size even if inode version does not
    change (Fate#318586).

  - ceph: update inode fields according to issued caps
    (Fate#318586).

  - ceph: use %zu for len in ceph_fill_inline_data()
    (Fate#318586).

  - ceph: use ceph_seq_cmp() to compare migrate_seq
    (Fate#318586).

  - ceph: use empty snap context for uninline_data and
    get_pool_perm (Fate#318586).

  - ceph: use fl->fl_file as owner identifier of flock and
    posix lock (Fate#318586).

  - ceph: use fl->fl_type to decide flock operation
    (Fate#318586).

  - ceph: use fpos_cmp() to compare dentry positions
    (Fate#318586).

  - ceph: use getattr request to fetch inline data
    (Fate#318586).

  - ceph: use i_size_{read,write} to get/set i_size
    (Fate#318586).

  - ceph: use msecs_to_jiffies for time conversion
    (Fate#318586).

  - ceph: use pagelist to present MDS request data
    (Fate#318586).

  - ceph: use truncate_pagecache() instead of
    truncate_inode_pages() (Fate#318586).

  - ceph_sync_{,direct_}write: fix an oops on
    ceph_osdc_new_request() failure (Fate#318586).

  - client: include kernel version in client metadata
    (Fate#318586).

  - cpuset: Fix potential deadlock w/ set_mems_allowed
    (bsc#960857, bsc#974646).

  - crush: add chooseleaf_stable tunable (Fate#318586).

  - crush: decode and initialize chooseleaf_stable
    (Fate#318586).

  - crush: ensure bucket id is valid before indexing buckets
    array (Fate#318586).

  - crush: ensure take bucket value is valid (Fate#318586).

  - crush: fix crash from invalid 'take' argument
    (Fate#318586).

  - crush: sync up with userspace (Fate#318586).

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

  - fs/ceph/debugfs.c: replace seq_printf by seq_puts
    (Fate#318586).

  - fs/ceph: replace pr_warning by pr_warn (Fate#318586).

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

  - kabi/severities: Whitelist libceph and rbd
    (fate#318586).

  - kabi: kgr, add reserved fields (fate#313296).

  - kabi: protect struct fc_rport_priv (bsc#953233,
    bsc#962846).

  - kabi: protect struct netns_ipv6 after FIB6 GC series
    (bsc#965319).

  - kgr: add TAINT_KGRAFT (fate#313296).

  - kgr: add kgraft annotation to hwrng kthread
    (fate#313296).

  - kgr: add kgraft annotations to kthreads'
    wait_event_freezable() API calls (fate#313296).

  - kgr: add objname to kgr_patch_fun struct (fate#313296).

  - kgr: add sympos and objname to error and debug messages
    (fate#313296).

  - kgr: add sympos as disambiguator field to kgr_patch_fun
    structure (fate#313296).

  - kgr: add sympos to sysfs (fate#313296).

  - kgr: call kgr_init_ftrace_ops() only for loaded objects
    (fate#313296).

  - kgr: change to kallsyms_on_each_symbol iterator
    (fate#313296).

  - kgr: define pr_fmt and modify all pr_* messages
    (fate#313296).

  - kgr: do not print error for !abort_if_missing symbols
    (bnc#943989).

  - kgr: do not return and print an error only if the object
    is not loaded (fate#313296).

  - kgr: do not use WQ_MEM_RECLAIM workqueue (bnc#963572).

  - kgr: fix an asymmetric dealing with delayed module
    loading (fate#313296).

  - kgr: fix redirection on s390x arch (bsc#903279).

  - kgr: fix reversion of a patch already reverted by a
    replace_all patch (fate#313296).

  - kgr: fix subtle race with kgr_module_init(), going
    notifier and kgr_modify_kernel() (fate#313296).

  - kgr: handle btrfs kthreads (fate#313296 bnc#889207).

  - kgr: kmemleak, really mark the kthread safe after an
    interrupt (fate#313296).

  - kgr: log when modifying kernel (fate#317827).

  - kgr: mark kernel unsupported upon patch revert
    (fate#313296).

  - kgr: mark some more missed kthreads (bnc#962336).

  - kgr: remove abort_if_missing flag (fate#313296).

  - kgr: usb/storage: do not emit thread awakened
    (bnc#899908).

  - kgraft/gfs2: Do not block livepatching in the log daemon
    for too long (fate#313296).

  - kgraft/xen: Do not block livepatching in the XEN blkif
    kthread (fate#313296).

  - libceph: Avoid holding the zero page on
    ceph_msgr_slab_init errors (Fate#318586).

  - libceph: Fix ceph_tcp_sendpage()'s more boolean usage
    (Fate#318586).

  - libceph: MOSDOpReply v7 encoding (Fate#318586).

  - libceph: Remove spurious kunmap() of the zero page
    (Fate#318586).

  - libceph: a couple tweaks for wait loops (Fate#318586).

  - libceph: add nocephx_sign_messages option (Fate#318586).

  - libceph: advertise support for TUNABLES5 (Fate#318586).

  - libceph: advertise support for keepalive2 (Fate#318586).

  - libceph: allow setting osd_req_op's flags (Fate#318586).

  - libceph: check data_len in ->alloc_msg() (Fate#318586).

  - libceph: clear messenger auth_retry flag if we fault
    (Fate#318586).

  - libceph: clear msg->con in ceph_msg_release() only
    (Fate#318586).

  - libceph: do not access invalid memory in keepalive2 path
    (Fate#318586).

  - libceph: do not spam dmesg with stray reply warnings
    (Fate#318586).

  - libceph: drop authorizer check from cephx msg signing
    routines (Fate#318586).

  - libceph: evaluate osd_req_op_data() arguments only once
    (Fate#318586).

  - libceph: fix authorizer invalidation, take 2
    (Fate#318586).

  - libceph: fix ceph_msg_revoke() (Fate#318586).

  - libceph: fix wrong name 'Ceph filesystem for Linux'
    (Fate#318586).

  - libceph: handle writefull for OSD op extent init
    (bsc#980706).

  - libceph: introduce ceph_x_authorizer_cleanup()
    (Fate#318586).

  - libceph: invalidate AUTH in addition to a service ticket
    (Fate#318586).

  - libceph: kill off ceph_x_ticket_handler::validity
    (Fate#318586).

  - libceph: move ceph_file_layout helpers to ceph_fs.h
    (Fate#318586).

  - libceph: msg signing callouts do not need con argument
    (Fate#318586).

  - libceph: nuke time_sub() (Fate#318586).

  - libceph: properly release STAT request's raw_data_in
    (Fate#318586).

  - libceph: remove con argument in handle_reply()
    (Fate#318586).

  - libceph: remove outdated comment (Fate#318586).

  - libceph: remove the unused macro AES_KEY_SIZE
    (Fate#318586).

  - libceph: rename con_work() to ceph_con_workfn()
    (Fate#318586).

  - libceph: set 'exists' flag for newly up osd
    (Fate#318586).

  - libceph: stop duplicating client fields in messenger
    (Fate#318586).

  - libceph: store timeouts in jiffies, verify user input
    (Fate#318586).

  - libceph: treat sockaddr_storage with uninitialized
    family as blank (Fate#318586).

  - libceph: use keepalive2 to verify the mon session is
    alive (Fate#318586).

  - libceph: use list_for_each_entry_safe (Fate#318586).

  - libceph: use list_next_entry instead of list_entry_next
    (Fate#318586).

  - libceph: use local variable cursor instead of
    msg->cursor (Fate#318586).

  - libceph: use the right footer size when skipping a
    message (Fate#318586).

  - libfc: replace 'rp_mutex' with 'rp_lock' (bsc#953233,
    bsc#962846).

  - mds: check cap ID when handling cap export message
    (Fate#318586).

  - mmc: Allow forward compatibility for eMMC (bnc#966054).

  - mmc: sdhci: Allow for irq being shared (bnc#977582).

  - mpt3sas: Fix use sas_is_tlr_enabled API before enabling
    MPI2_SCSIIO_CONTROL_TLR_ON flag (bsc#967640).

  - nfs-rdma: Fix for FMR leaks (bsc#908151).

  - nfs: fix high load average due to callback thread
    sleeping (bsc#971170).

  - nvme: fix max_segments integer truncation (bsc#976471).

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

  - rbd: bump queue_max_segments (Fate#318586).

  - rbd: delete an unnecessary check before
    rbd_dev_destroy() (Fate#318586).

  - rbd: do not free rbd_dev outside of the release callback
    (Fate#318586).

  - rbd: do not put snap_context twice in rbd_queue_workfn()
    (Fate#318586).

  - rbd: drop null test before destroy functions
    (Fate#318586).

  - rbd: handle OBJ_REQUEST_SG types for copyup
    (bsc#983394).

  - rbd: plug rbd_dev->header.object_prefix memory leak
    (Fate#318586).

  - rbd: rbd_wq comment is obsolete (Fate#318586).

  - rbd: remove duplicate calls to rbd_dev_mapping_clear()
    (Fate#318586).

  - rbd: report unsupported features to syslog (bsc#979169).

  - rbd: return -ENOMEM instead of pool id if
    rbd_dev_create() fails (Fate#318586).

  - rbd: set device_type::release instead of device::release
    (Fate#318586).

  - rbd: set max_sectors explicitly (Fate#318586).

  - rbd: store rbd_options in rbd_device (Fate#318586).

  - rbd: terminate rbd_opts_tokens with Opt_err
    (Fate#318586).

  - rbd: timeout watch teardown on unmap with mount_timeout
    (Fate#318586).

  - rbd: use GFP_NOIO consistently for request allocations
    (bsc#971159).

  - rbd: use writefull op for object size writes
    (Fate#318586).

  - reduce m_start() cost.. (bsc#966573).

  - rpm/modprobe-xen.conf: Revert comment change to allow
    parallel install (bsc#957986). This reverts commit
    6c6d86d3cdc26f7746fe4ba2bef8859b5aeb346c.

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

  - supported.conf :

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

  - target/rbd: do not put snap_context twice (bsc#981143).

  - target/rbd: remove caw_mutex usage (bsc#981143).

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

  - xen: Linux 3.12.58.

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
    (bsc#908151)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=889207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=897662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=899908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=903279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=928547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=940413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=942262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=943989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=944309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983394"
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
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/12");
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

if ( rpm_check(release:"SUSE13.1", reference:"cloop-2.639-11.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-debuginfo-2.639-11.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-debugsource-2.639-11.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-default-2.639_k3.12.59_47-11.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-default-debuginfo-2.639_k3.12.59_47-11.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-desktop-2.639_k3.12.59_47-11.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-desktop-debuginfo-2.639_k3.12.59_47-11.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-pae-2.639_k3.12.59_47-11.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-pae-debuginfo-2.639_k3.12.59_47-11.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-xen-2.639_k3.12.59_47-11.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-xen-debuginfo-2.639_k3.12.59_47-11.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-7.0.2-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-debuginfo-7.0.2-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-debugsource-7.0.2-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-devel-7.0.2-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-eppic-7.0.2-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-eppic-debuginfo-7.0.2-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-gcore-7.0.2-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-gcore-debuginfo-7.0.2-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-default-7.0.2_k3.12.59_47-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-default-debuginfo-7.0.2_k3.12.59_47-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-desktop-7.0.2_k3.12.59_47-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-desktop-debuginfo-7.0.2_k3.12.59_47-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-pae-7.0.2_k3.12.59_47-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-pae-debuginfo-7.0.2_k3.12.59_47-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-xen-7.0.2_k3.12.59_47-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-xen-debuginfo-7.0.2_k3.12.59_47-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-debugsource-1.28-16.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-default-1.28_k3.12.59_47-16.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-default-debuginfo-1.28_k3.12.59_47-16.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-desktop-1.28_k3.12.59_47-16.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-desktop-debuginfo-1.28_k3.12.59_47-16.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-pae-1.28_k3.12.59_47-16.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-pae-debuginfo-1.28_k3.12.59_47-16.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-xen-1.28_k3.12.59_47-16.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-xen-debuginfo-1.28_k3.12.59_47-16.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-6.21.1-2.34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-debuginfo-6.21.1-2.34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-debugsource-6.21.1-2.34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-devel-6.21.1-2.34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-default-6.21.1_k3.12.59_47-2.34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-default-debuginfo-6.21.1_k3.12.59_47-2.34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-desktop-6.21.1_k3.12.59_47-2.34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-desktop-debuginfo-6.21.1_k3.12.59_47-2.34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-pae-6.21.1_k3.12.59_47-2.34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-pae-debuginfo-6.21.1_k3.12.59_47-2.34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-xen-6.21.1_k3.12.59_47-2.34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-xen-debuginfo-6.21.1_k3.12.59_47-2.34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-1.4.20.3-13.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-debuginfo-1.4.20.3-13.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-debugsource-1.4.20.3-13.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-default-1.4.20.3_k3.12.59_47-13.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-default-debuginfo-1.4.20.3_k3.12.59_47-13.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-desktop-1.4.20.3_k3.12.59_47-13.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-desktop-debuginfo-1.4.20.3_k3.12.59_47-13.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-pae-1.4.20.3_k3.12.59_47-13.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-pae-debuginfo-1.4.20.3_k3.12.59_47-13.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-xen-1.4.20.3_k3.12.59_47-13.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-xen-debuginfo-1.4.20.3_k3.12.59_47-13.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-base-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-base-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-debugsource-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-devel-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-devel-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-macros-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-source-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-source-vanilla-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-syms-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libipset3-6.21.1-2.34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libipset3-debuginfo-6.21.1-2.34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-1.58-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-debuginfo-1.58-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-debugsource-1.58-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-default-1.58_k3.12.59_47-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-default-debuginfo-1.58_k3.12.59_47-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-desktop-1.58_k3.12.59_47-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-desktop-debuginfo-1.58_k3.12.59_47-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-pae-1.58_k3.12.59_47-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-pae-debuginfo-1.58_k3.12.59_47-31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-1.11.0-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-controller-1.11.0-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-controller-debuginfo-1.11.0-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-debuginfo-1.11.0-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-debugsource-1.11.0-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-default-1.11.0_k3.12.59_47-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-default-debuginfo-1.11.0_k3.12.59_47-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-desktop-1.11.0_k3.12.59_47-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-desktop-debuginfo-1.11.0_k3.12.59_47-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-pae-1.11.0_k3.12.59_47-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-pae-debuginfo-1.11.0_k3.12.59_47-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-xen-1.11.0_k3.12.59_47-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-xen-debuginfo-1.11.0_k3.12.59_47-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-pki-1.11.0-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-switch-1.11.0-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-switch-debuginfo-1.11.0-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-test-1.11.0-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-0.44-258.31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-debuginfo-0.44-258.31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-debugsource-0.44-258.31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-default-0.44_k3.12.59_47-258.31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-default-debuginfo-0.44_k3.12.59_47-258.31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-desktop-0.44_k3.12.59_47-258.31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-desktop-debuginfo-0.44_k3.12.59_47-258.31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-pae-0.44_k3.12.59_47-258.31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-pae-debuginfo-0.44_k3.12.59_47-258.31.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-openvswitch-1.11.0-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-openvswitch-test-1.11.0-0.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-virtualbox-4.2.36-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-virtualbox-debuginfo-4.2.36-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-debugsource-20130607-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-default-20130607_k3.12.59_47-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-default-debuginfo-20130607_k3.12.59_47-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-desktop-20130607_k3.12.59_47-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-desktop-debuginfo-20130607_k3.12.59_47-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-pae-20130607_k3.12.59_47-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-pae-debuginfo-20130607_k3.12.59_47-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-xen-20130607_k3.12.59_47-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-xen-debuginfo-20130607_k3.12.59_47-2.30.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-4.2.36-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-debuginfo-4.2.36-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-debugsource-4.2.36-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-devel-4.2.36-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-default-4.2.36_k3.12.59_47-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-default-debuginfo-4.2.36_k3.12.59_47-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-desktop-4.2.36_k3.12.59_47-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-desktop-debuginfo-4.2.36_k3.12.59_47-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-pae-4.2.36_k3.12.59_47-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-pae-debuginfo-4.2.36_k3.12.59_47-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-tools-4.2.36-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-tools-debuginfo-4.2.36-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-x11-4.2.36-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-x11-debuginfo-4.2.36-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-default-4.2.36_k3.12.59_47-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-default-debuginfo-4.2.36_k3.12.59_47-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-desktop-4.2.36_k3.12.59_47-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-desktop-debuginfo-4.2.36_k3.12.59_47-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-pae-4.2.36_k3.12.59_47-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-pae-debuginfo-4.2.36_k3.12.59_47-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-source-4.2.36-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-qt-4.2.36-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-qt-debuginfo-4.2.36-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-websrv-4.2.36-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-websrv-debuginfo-4.2.36-2.62.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-debugsource-4.3.4_10-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-devel-4.3.4_10-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-default-4.3.4_10_k3.12.59_47-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-default-debuginfo-4.3.4_10_k3.12.59_47-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-desktop-4.3.4_10_k3.12.59_47-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-desktop-debuginfo-4.3.4_10_k3.12.59_47-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-pae-4.3.4_10_k3.12.59_47-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-pae-debuginfo-4.3.4_10_k3.12.59_47-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-libs-4.3.4_10-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-libs-debuginfo-4.3.4_10-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-tools-domU-4.3.4_10-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-tools-domU-debuginfo-4.3.4_10-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-2.3-2.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-debuginfo-2.3-2.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-debugsource-2.3-2.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-default-2.3_k3.12.59_47-2.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-default-debuginfo-2.3_k3.12.59_47-2.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-desktop-2.3_k3.12.59_47-2.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-desktop-debuginfo-2.3_k3.12.59_47-2.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-pae-2.3_k3.12.59_47-2.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-pae-debuginfo-2.3_k3.12.59_47-2.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-xen-2.3_k3.12.59_47-2.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-xen-debuginfo-2.3_k3.12.59_47-2.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-base-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-debugsource-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-devel-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-base-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-debugsource-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-devel-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-base-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-debugsource-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-devel-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-base-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-debugsource-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-devel-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-base-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-base-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-debugsource-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-devel-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-debugsource-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-devel-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-base-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-debugsource-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-devel-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-base-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-debugsource-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-devel-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-base-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-devel-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-base-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-devel-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-base-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-debugsource-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-devel-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-base-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-base-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-debugsource-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-devel-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-devel-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-base-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.59-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-4.3.4_10-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-doc-html-4.3.4_10-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-libs-32bit-4.3.4_10-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.3.4_10-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-tools-4.3.4_10-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-tools-debuginfo-4.3.4_10-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-xend-tools-4.3.4_10-63.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-xend-tools-debuginfo-4.3.4_10-63.1") ) flag++;

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
