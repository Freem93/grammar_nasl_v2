#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1360-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(100320);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/22 13:36:33 $");

  script_cve_id("CVE-2015-1350", "CVE-2016-10044", "CVE-2016-10200", "CVE-2016-10208", "CVE-2016-2117", "CVE-2016-3070", "CVE-2016-5243", "CVE-2016-7117", "CVE-2016-9191", "CVE-2016-9588", "CVE-2016-9604", "CVE-2017-2647", "CVE-2017-2671", "CVE-2017-5669", "CVE-2017-5897", "CVE-2017-5986", "CVE-2017-6074", "CVE-2017-6214", "CVE-2017-6345", "CVE-2017-6346", "CVE-2017-6348", "CVE-2017-6353", "CVE-2017-6951", "CVE-2017-7187", "CVE-2017-7261", "CVE-2017-7294", "CVE-2017-7308", "CVE-2017-7616", "CVE-2017-7645", "CVE-2017-8106");
  script_osvdb_id(117818, 135961, 138215, 139499, 145048, 146761, 147763, 148861, 151554, 151568, 152094, 152302, 152453, 152521, 152685, 152705, 152709, 152728, 152729, 153065, 153884, 154043, 154359, 154384, 154548, 154627, 154633, 155190, 155910, 156266, 156736);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2017:1360-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 SP1 kernel was updated to 3.12.74 to
receive various security and bugfixes. Notable new/improved features :

  - Improved support for Hyper-V

  - Support for the tcp_westwood TCP scheduling algorithm
    The following security bugs were fixed :

  - CVE-2017-8106: The handle_invept function in
    arch/x86/kvm/vmx.c in the Linux kernel allowed
    privileged KVM guest OS users to cause a denial of
    service (NULL pointer dereference and host OS crash) via
    a single-context INVEPT instruction with a NULL EPT
    pointer (bsc#1035877).

  - CVE-2017-6951: The keyring_search_aux function in
    security/keys/keyring.c in the Linux kernel allowed
    local users to cause a denial of service (NULL pointer
    dereference and OOPS) via a request_key system call for
    the 'dead' type. (bsc#1029850).

  - CVE-2017-2647: The KEYS subsystem in the Linux kernel
    allowed local users to gain privileges or cause a denial
    of service (NULL pointer dereference and system crash)
    via vectors involving a NULL value for a certain match
    field, related to the keyring_search_iterator function
    in keyring.c. (bsc#1030593)

  - CVE-2016-9604: This fixes handling of keyrings starting
    with '.' in KEYCTL_JOIN_SESSION_KEYRING, which could
    have allowed local users to manipulate privileged
    keyrings (bsc#1035576)

  - CVE-2017-7616: Incorrect error handling in the
    set_mempolicy and mbind compat syscalls in
    mm/mempolicy.c in the Linux kernel allowed local users
    to obtain sensitive information from uninitialized stack
    data by triggering failure of a certain bitmap
    operation. (bnc#1033336).

  - CVE-2017-7645: The NFSv2/NFSv3 server in the nfsd
    subsystem in the Linux kernel allowed remote attackers
    to cause a denial of service (system crash) via a long
    RPC reply, related to net/sunrpc/svc.c,
    fs/nfsd/nfs3xdr.c, and fs/nfsd/nfsxdr.c. (bsc#1034670).

  - CVE-2017-7308: The packet_set_ring function in
    net/packet/af_packet.c in the Linux kernel did not
    properly validate certain block-size data, which allowed
    local users to cause a denial of service (overflow) or
    possibly have unspecified other impact via crafted
    system calls (bnc#1031579)

  - CVE-2017-2671: The ping_unhash function in
    net/ipv4/ping.c in the Linux kernel was too late in
    obtaining a certain lock and consequently could not
    ensure that disconnect function calls are safe, which
    allowed local users to cause a denial of service (panic)
    by leveraging access to the protocol value of
    IPPROTO_ICMP in a socket system call (bnc#1031003)

  - CVE-2017-7294: The vmw_surface_define_ioctl function in
    drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux
    kernel did not validate addition of certain levels data,
    which allowed local users to trigger an integer overflow
    and out-of-bounds write, and cause a denial of service
    (system hang or crash) or possibly gain privileges, via
    a crafted ioctl call for a /dev/dri/renderD* device
    (bnc#1031440)

  - CVE-2017-7261: The vmw_surface_define_ioctl function in
    drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux
    kernel did not check for a zero value of certain levels
    data, which allowed local users to cause a denial of
    service (ZERO_SIZE_PTR dereference, and GPF and possibly
    panic) via a crafted ioctl call for a /dev/dri/renderD*
    device (bnc#1031052)

  - CVE-2017-7187: The sg_ioctl function in
    drivers/scsi/sg.c in the Linux kernel allowed local
    users to cause a denial of service (stack-based buffer
    overflow) or possibly have unspecified other impact via
    a large command size in an SG_NEXT_CMD_LEN ioctl call,
    leading to out-of-bounds write access in the sg_write
    function (bnc#1030213)

  - CVE-2016-9588: arch/x86/kvm/vmx.c in the Linux kernel
    mismanaged the #BP and #OF exceptions, which allowed
    guest OS users to cause a denial of service (guest OS
    crash) by declining to handle an exception thrown by an
    L2 guest (bsc#1015703).

  - CVE-2017-5669: The do_shmat function in ipc/shm.c in the
    Linux kernel did not restrict the address calculated by
    a certain rounding operation, which allowed local users
    to map page zero, and consequently bypass a protection
    mechanism that exists for the mmap system call, by
    making crafted shmget and shmat system calls in a
    privileged context (bnc#1026914).

  - CVE-2016-10200: Race condition in the L2TPv3 IP
    Encapsulation feature in the Linux kernel allowed local
    users to gain privileges or cause a denial of service
    (use-after-free) by making multiple bind system calls
    without properly ascertaining whether a socket has the
    SOCK_ZAPPED status, related to net/l2tp/l2tp_ip.c and
    net/l2tp/l2tp_ip6.c (bnc#1028415)

  - CVE-2016-10208: The ext4_fill_super function in
    fs/ext4/super.c in the Linux kernel did not properly
    validate meta block groups, which allowed physically
    proximate attackers to cause a denial of service
    (out-of-bounds read and system crash) via a crafted ext4
    image (bnc#1023377).

  - CVE-2017-5897: The ip6gre_err function in
    net/ipv6/ip6_gre.c in the Linux kernel allowed remote
    attackers to have unspecified impact via vectors
    involving GRE flags in an IPv6 packet, which trigger an
    out-of-bounds access (bsc#1023762).

  - CVE-2017-5986: A race condition in the
    sctp_wait_for_sndbuf function in net/sctp/socket.c in
    the Linux kernel allowed local users to cause a denial
    of service (assertion failure and panic) via a
    multithreaded application that peels off an association
    in a certain buffer-full state (bsc#1025235).

  - CVE-2017-6074: The dccp_rcv_state_process function in
    net/dccp/input.c in the Linux kernel mishandled
    DCCP_PKT_REQUEST packet data structures in the LISTEN
    state, which allowed local users to obtain root
    privileges or cause a denial of service (double free)
    via an application that made an IPV6_RECVPKTINFO
    setsockopt system call (bnc#1026024)

  - CVE-2016-9191: The cgroup offline implementation in the
    Linux kernel mishandled certain drain operations, which
    allowed local users to cause a denial of service (system
    hang) by leveraging access to a container environment
    for executing a crafted application (bnc#1008842)

  - CVE-2017-6348: The hashbin_delete function in
    net/irda/irqueue.c in the Linux kernel improperly
    managed lock dropping, which allowed local users to
    cause a denial of service (deadlock) via crafted
    operations on IrDA devices (bnc#1027178).

  - CVE-2016-10044: The aio_mount function in fs/aio.c in
    the Linux kernel did not properly restrict execute
    access, which made it easier for local users to bypass
    intended SELinux W^X policy restrictions, and
    consequently gain privileges, via an io_setup system
    call (bnc#1023992).

  - CVE-2016-3070: The trace_writeback_dirty_page
    implementation in include/trace/events/writeback.h in
    the Linux kernel improperly interacts with mm/migrate.c,
    which allowed local users to cause a denial of service
    (NULL pointer dereference and system crash) or possibly
    have unspecified other impact by triggering a certain
    page move (bnc#979215).

  - CVE-2016-5243: The tipc_nl_compat_link_dump function in
    net/tipc/netlink_compat.c in the Linux kernel did not
    properly copy a certain string, which allowed local
    users to obtain sensitive information from kernel stack
    memory by reading a Netlink message (bnc#983212).

  - CVE-2017-6345: The LLC subsystem in the Linux kernel did
    not ensure that a certain destructor exists in required
    circumstances, which allowed local users to cause a
    denial of service (BUG_ON) or possibly have unspecified
    other impact via crafted system calls (bnc#1027190)

  - CVE-2017-6346: Race condition in net/packet/af_packet.c
    in the Linux kernel allowed local users to cause a
    denial of service (use-after-free) or possibly have
    unspecified other impact via a multithreaded application
    that made PACKET_FANOUT setsockopt system calls
    (bnc#1027189)

  - CVE-2017-6353: net/sctp/socket.c in the Linux kernel did
    not properly restrict association peel-off operations
    during certain wait states, which allowed local users to
    cause a denial of service (invalid unlock and double
    free) via a multithreaded application. NOTE: this
    vulnerability exists because of an incorrect fix for
    CVE-2017-5986 (bnc#1027066)

  - CVE-2017-5986: Race condition in the
    sctp_wait_for_sndbuf function in net/sctp/socket.c in
    the Linux kernel allowed local users to cause a denial
    of service (assertion failure and panic) via a
    multithreaded application that peels off an association
    in a certain buffer-full state (bsc#1025235).

  - CVE-2017-6214: The tcp_splice_read function in
    net/ipv4/tcp.c in the Linux kernel allowed remote
    attackers to cause a denial of service (infinite loop
    and soft lockup) via vectors involving a TCP packet with
    the URG flag (bnc#1026722)

  - CVE-2016-2117: The atl2_probe function in
    drivers/net/ethernet/atheros/atlx/atl2.c in the Linux
    kernel incorrectly enables scatter/gather I/O, which
    allowed remote attackers to obtain sensitive information
    from kernel memory by reading packet data (bnc#968697)

  - CVE-2015-1350: The VFS subsystem in the Linux kernel
    provided an incomplete set of requirements for setattr
    operations that underspecifies removing extended
    privilege attributes, which allowed local users to cause
    a denial of service (capability stripping) via a failed
    invocation of a system call, as demonstrated by using
    chown to remove a capability from the ping or Wireshark
    dumpcap program (bsc#914939).

  - CVE-2016-7117: Use-after-free vulnerability in the
    __sys_recvmmsg function in net/socket.c in the Linux
    kernel allowed remote attackers to execute arbitrary
    code via vectors involving a recvmmsg system call that
    is mishandled during error processing (bsc#1003077). The
    following non-security bugs were fixed :

  - ACPI / APEI: Fix NMI notification handling (bsc#917630).

  - arch: Mass conversion of smp_mb__*() (bsc#1020795).

  - asm-generic: add __smp_xxx wrappers (bsc#1020795).

  - block: remove struct request buffer member
    (bsc#1020795).

  - block: submit_bio_wait() conversions (bsc#1020795).

  - bonding: Advertize vxlan offload features when supported
    (bsc#1009682).

  - bonding: handle more gso types (bsc#1009682).

  - bonding: use the correct ether type for alb
    (bsc#1028595).

  - btrfs: allow unlink to exceed subvolume quota
    (bsc#1015821).

  - btrfs: Change qgroup_meta_rsv to 64bit (bsc#1015821).

  - btrfs: fix btrfs_compat_ioctl failures on non-compat
    ioctls (bsc#1018100).

  - btrfs: make file clone aware of fatal signals
    (bsc#1015787).

  - btrfs: qgroups: Retry after commit on getting EDQUOT
    (bsc#1015821).

  - cancel the setfilesize transation when io error happen
    (bsc#1028648).

  - cgroup: remove stray references to css_id (bsc#1020795).

  - cpuidle: powernv/pseries: Auto-promotion of snooze to
    deeper idle state (bnc#1023164).

  - dm: add era target (bsc#1020795).

  - dm: allow remove to be deferred (bsc#1020795).

  - dm bitset: only flush the current word if it has been
    dirtied (bsc#1020795).

  - dm btree: add dm_btree_find_lowest_key (bsc#1020795).

  - dm cache: actually resize cache (bsc#1020795).

  - dm cache: add block sizes and total cache blocks to
    status output (bsc#1020795).

  - dm cache: add cache block invalidation support
    (bsc#1020795).

  - dm cache: add passthrough mode (bsc#1020795).

  - dm cache: add policy name to status output
    (bsc#1020795).

  - dm cache: add remove_cblock method to policy interface
    (bsc#1020795).

  - dm cache: be much more aggressive about promoting writes
    to discarded blocks (bsc#1020795).

  - dm cache: cache shrinking support (bsc#1020795).

  - dm cache: do not add migration to completed list before
    unhooking bio (bsc#1020795).

  - dm cache: fix a lock-inversion (bsc#1020795).

  - dm cache: fix truncation bug when mapping I/O to more
    than 2TB fast device (bsc#1020795).

  - dm cache: fix writethrough mode quiescing in cache_map
    (bsc#1020795).

  - dm cache: improve efficiency of quiescing flag
    management (bsc#1020795).

  - dm cache: io destined for the cache device can now serve
    as tick bios (bsc#1020795).

  - dm cache: log error message if dm_kcopyd_copy() fails
    (bsc#1020795).

  - dm cache metadata: check the metadata version when
    reading the superblock (bsc#1020795).

  - dm cache metadata: return bool from
    __superblock_all_zeroes (bsc#1020795).

  - dm cache: move hook_info into common portion of
    per_bio_data structure (bsc#1020795).

  - dm cache: optimize commit_if_needed (bsc#1020795).

  - dm cache policy mq: a few small fixes (bsc#1020795).

  - dm cache policy mq: fix promotions to occur as expected
    (bsc#1020795).

  - dm cache policy mq: implement writeback_work() and
    mq_{set,clear}_dirty() (bsc#1020795).

  - dm cache policy mq: introduce three promotion threshold
    tunables (bsc#1020795).

  - dm cache policy mq: protect residency method with
    existing mutex (bsc#1020795).

  - dm cache policy mq: reduce memory requirements
    (bsc#1020795).

  - dm cache policy mq: use list_del_init instead of
    list_del + INIT_LIST_HEAD (bsc#1020795).

  - dm cache policy: remove return from void
    policy_remove_mapping (bsc#1020795).

  - dm cache: promotion optimisation for writes
    (bsc#1020795).

  - dm cache: resolve small nits and improve Documentation
    (bsc#1020795).

  - dm cache: return -EINVAL if the user specifies unknown
    cache policy (bsc#1020795).

  - dm cache: use cell_defer() boolean argument consistently
    (bsc#1020795).

  - dm: change sector_count member in clone_info from
    sector_t to unsigned (bsc#1020795).

  - dm crypt: add TCW IV mode for old CBC TCRYPT containers
    (bsc#1020795).

  - dm crypt: properly handle extra key string in
    initialization (bsc#1020795).

  - dm delay: use per-bio data instead of a mempool and slab
    cache (bsc#1020795).

  - dm: fix Kconfig indentation (bsc#1020795).

  - dm: fix Kconfig menu indentation (bsc#1020795).

  - dm: make dm_table_alloc_md_mempools static
    (bsc#1020795).

  - dm mpath: do not call pg_init when it is already running
    (bsc#1020795).

  - dm mpath: fix lock order inconsistency in
    multipath_ioctl (bsc#1020795).

  - dm mpath: print more useful warnings in
    multipath_message() (bsc#1020795).

  - dm mpath: push back requests instead of queueing
    (bsc#1020795).

  - dm mpath: really fix lockdep warning (bsc#1020795).

  - dm mpath: reduce memory pressure when requeuing
    (bsc#1020795).

  - dm mpath: remove extra nesting in map function
    (bsc#1020795).

  - dm mpath: remove map_io() (bsc#1020795).

  - dm mpath: remove process_queued_ios() (bsc#1020795).

  - dm mpath: requeue I/O during pg_init (bsc#1020795).

  - dm persistent data: cleanup dm-thin specific references
    in text (bsc#1020795).

  - dm snapshot: call destroy_work_on_stack() to pair with
    INIT_WORK_ONSTACK() (bsc#1020795).

  - dm snapshot: fix metadata corruption (bsc#1020795).

  - dm snapshot: prepare for switch to using dm-bufio
    (bsc#1020795).

  - dm snapshot: use dm-bufio (bsc#1020795).

  - dm snapshot: use dm-bufio prefetch (bsc#1020795).

  - dm snapshot: use GFP_KERNEL when initializing exceptions
    (bsc#1020795).

  - dm space map disk: optimise sm_disk_dec_block
    (bsc#1020795).

  - dm space map metadata: limit errors in
    sm_metadata_new_block (bsc#1020795).

  - dm: stop using bi_private (bsc#1020795).

  - dm table: add dm_table_run_md_queue_async (bsc#1020795).

  - dm table: print error on preresume failure
    (bsc#1020795).

  - dm table: remove unused buggy code that extends the
    targets array (bsc#1020795).

  - dm thin: add error_if_no_space feature (bsc#1020795).

  - dm thin: add mappings to end of prepared_* lists
    (bsc#1020795).

  - dm thin: add 'no_space_timeout' dm-thin-pool module
    param (bsc#1020795).

  - dm thin: add timeout to stop out-of-data-space mode
    holding IO forever (bsc#1020795).

  - dm thin: allow metadata commit if pool is in
    PM_OUT_OF_DATA_SPACE mode (bsc#1020795).

  - dm thin: allow metadata space larger than supported to
    go unused (bsc#1020795).

  - dm thin: cleanup and improve no space handling
    (bsc#1020795).

  - dm thin: eliminate the no_free_space flag (bsc#1020795).

  - dm thin: ensure user takes action to validate data and
    metadata consistency (bsc#1020795).

  - dm thin: factor out check_low_water_mark and use bools
    (bsc#1020795).

  - dm thin: fix deadlock in __requeue_bio_list
    (bsc#1020795).

  - dm thin: fix noflush suspend IO queueing (bsc#1020795).

  - dm thin: fix out of data space handling (bsc#1020795).

  - dm thin: fix pool feature parsing (bsc#1020795).

  - dm thin: fix rcu_read_lock being held in code that can
    sleep (bsc#1020795).

  - dm thin: handle metadata failures more consistently
    (bsc#1020795).

  - dm thin: irqsave must always be used with the pool->lock
    spinlock (bsc#1020795).

  - dm thin: log info when growing the data or metadata
    device (bsc#1020795).

  - dm thin: requeue bios to DM core if no_free_space and in
    read-only mode (bsc#1020795).

  - dm thin: return error from alloc_data_block if pool is
    not in write mode (bsc#1020795).

  - dm thin: simplify pool_is_congested (bsc#1020795).

  - dm thin: sort the per thin deferred bios using an
    rb_tree (bsc#1020795).

  - dm thin: synchronize the pool mode during suspend
    (bsc#1020795).

  - dm thin: use bool rather than unsigned for flags in
    structures (bsc#1020795).

  - dm thin: use INIT_WORK_ONSTACK in noflush_work to avoid
    ODEBUG warning (bsc#1020795).

  - dm thin: use per thin device deferred bio lists
    (bsc#1020795).

  - dm: use RCU_INIT_POINTER instead of rcu_assign_pointer
    in __unbind (bsc#1020795).

  - drm/i915: relax uncritical udelay_range() (bsc#1038261).

  - ether: add loopback type ETH_P_LOOPBACK (bsc#1028595).

  - ext4: fix bh leak on error paths in ext4_rename() and
    ext4_cross_rename() (bsc#1012985).

  - ext4: fix fencepost in s_first_meta_bg validation
    (bsc#1029986).

  - ext4: mark inode dirty after converting inline directory
    (bsc#1012985).

  - ftrace: Make ftrace_location_range() global
    (FATE#322421).

  - HID: usbhid: improve handling of Clear-Halt and reset
    (bsc#1031080).

  - hv: util: catch allocation errors

  - hv: utils: use memdup_user in hvt_op_write

  - hwrng: virtio - ensure reads happen after successful
    probe (bsc#954763 bsc#1032344).

  - i40e: avoid NULL pointer dereference (bsc#922853).

  - i40e/i40evf: Break up xmit_descriptor_count from
    maybe_stop_tx (bsc#985561).

  - i40e/i40evf: Limit TSO to 7 descriptors for payload
    instead of 8 per packet (bsc#985561).

  - i40e/i40evf: Rewrite logic for 8 descriptor per packet
    check (bsc#985561).

  - i40e: Impose a lower limit on gso size (bsc#985561).

  - i40e: Limit TX descriptor count in cases where frag size
    is greater than 16K (bsc#985561).

  - iommu/vt-d: Flush old iommu caches for kdump when the
    device gets context mapped (bsc#1023824).

  - iommu/vt-d: Tylersburg isoch identity map check is done
    too late (bsc#1032125).

  - ipv6: make ECMP route replacement less greedy
    (bsc#930399).

  - kabi: hide changes in struct sk_buff (bsc#1009682).

  - KABI: Hide new include in arch/powerpc/kernel/process.c
    (fate#322421).

  - kABI: mask struct xfs_icdinode change (bsc#1024788).

  - kABI: protect struct inet6_dev (kabi).

  - kABI: protect struct iscsi_conn (bsc#103470).

  - kABI: protect struct xfs_buftarg and struct xfs_mount
    (bsc#1024508).

  - kABI: restore can_rx_register parameters (kabi).

  - kernel/watchdog: use nmi registers snapshot in
    hardlockup handler (bsc#940946, bsc#937444).

  - kgr: Mark eeh_event_handler() kthread safe using a
    timeout (bsc#1031662).

  - kgr/module: make a taint flag module-specific

  - kgr: remove unneeded kgr_needs_lazy_migration() s390x
    definition

  - l2tp: fix address test in __l2tp_ip6_bind_lookup()
    (bsc#1028415).

  - l2tp: fix lookup for sockets not bound to a device in
    l2tp_ip (bsc#1028415).

  - l2tp: fix racy socket lookup in l2tp_ip and l2tp_ip6
    bind() (bsc#1028415).

  - l2tp: hold socket before dropping lock in l2tp_ip{,
    6}_recv() (bsc#1028415).

  - l2tp: hold tunnel socket when handling control frames in
    l2tp_ip and l2tp_ip6 (bsc#1028415).

  - l2tp: lock socket before checking flags in connect()
    (bsc#1028415).

  - livepatch: Allow architectures to specify an alternate
    ftrace location (FATE#322421).

  - locking/semaphore: Add down_interruptible_timeout()
    (bsc#1031662).

  - md: avoid oops on unload if some process is in poll or
    select (bsc#1020795).

  - md: Convert use of typedef ctl_table to struct ctl_table
    (bsc#1020795).

  - md: ensure metadata is writen after raid level change
    (bsc#1020795).

  - md linear: fix a race between linear_add() and
    linear_congested() (bsc#1018446).

  - md: md_clear_badblocks should return an error code on
    failure (bsc#1020795).

  - md: refuse to change shape of array if it is active but
    read-only (bsc#1020795).

  - megaraid_sas: add missing curly braces in ioctl handler
    (bsc#1023207).

  - megaraid_sas: Fixup tgtid count in
    megasas_ld_list_query() (bsc#971933).

  - mm/huge_memory.c: respect FOLL_FORCE/FOLL_COW for thp
    (bnc#1030118).

  - mm, memcg: do not retry precharge charges (bnc#1022559).

  - mm/mempolicy.c: do not put mempolicy before using its
    nodemask (References: VM Performance, bnc#931620).

  - mm/page_alloc: fix nodes for reclaim in fast path
    (bnc#1031842).

  - module: move add_taint_module() to a header file

  - net: Add skb_gro_postpull_rcsum to udp and vxlan
    (bsc#1009682).

  - net: add skb_pop_rcv_encapsulation (bsc#1009682).

  - net: Call skb_checksum_init in IPv4 (bsc#1009682).

  - net: Call skb_checksum_init in IPv6 (bsc#1009682).

  - netfilter: allow logging fron non-init netns
    (bsc#970083).

  - net: Generalize checksum_init functions (bsc#1009682).

  - net: Preserve CHECKSUM_COMPLETE at validation
    (bsc#1009682).

  - NFS: do not try to cross a mountpount when there isn't
    one there (bsc#1028041).

  - NFS: Expedite unmount of NFS auto-mounts (bnc#1025802).

  - NFS: Fix a performance regression in readdir
    (bsc#857926).

  - NFS: flush out dirty data on file fput() (bsc#1021762).

  - ocfs2: do not write error flag to user structure we
    cannot copy from/to (bsc#1012985).

  - powerpc: Blacklist GCC 5.4 6.1 and 6.2 (boo#1028895).

  - powerpc: Create a helper for getting the kernel toc
    value (FATE#322421).

  - powerpc/fadump: Fix the race in crash_fadump()
    (bsc#1022971).

  - powerpc/fadump: Reserve memory at an offset closer to
    bottom of RAM (bsc#1032141).

  - powerpc/fadump: Update fadump documentation
    (bsc#1032141).

  - powerpc/ftrace: Add Kconfig & Make glue for
    mprofile-kernel (FATE#322421).

  - powerpc/ftrace: Add support for -mprofile-kernel ftrace
    ABI (FATE#322421).

  - powerpc/ftrace: Use $(CC_FLAGS_FTRACE) when disabling
    ftrace (FATE#322421).

  - powerpc/ftrace: Use generic ftrace_modify_all_code()
    (FATE#322421).

  - powerpc: introduce TIF_KGR_IN_PROGRESS thread flag
    (FATE#322421).

  - powerpc/kgraft: Add kgraft header (FATE#322421).

  - powerpc/kgraft: Add kgraft stack to struct thread_info
    (FATE#322421).

  - powerpc/kgraft: Add live patching support on ppc64le
    (FATE#322421).

  - powerpc/module: Create a special stub for
    ftrace_caller() (FATE#322421).

  - powerpc/module: Mark module stubs with a magic value
    (FATE#322421).

  - powerpc/module: Only try to generate the ftrace_caller()
    stub once (FATE#322421).

  - powerpc/modules: Never restore r2 for a mprofile-kernel
    style mcount() call (FATE#322421).

  - powerpc/prom: Increase minimum RMA size to 512MB
    (bsc#984530).

  - powerpc/pseries/cpuidle: Remove MAX_IDLE_STATE macro
    (bnc#1023164).

  - powerpc/pseries/cpuidle: Use cpuidle_register() for
    initialisation (bnc#1023164).

  - powerpc: Reject binutils 2.24 when building little
    endian (boo#1028895).

  - RAID1: avoid unnecessary spin locks in I/O barrier code
    (bsc#982783,bsc#1020048).

  - raid1: include bio_end_io_list in nr_queued to prevent
    freeze_array hang

  - remove mpath patches from dmcache backport, for
    bsc#1035738

  - revert 'procfs: mark thread stack correctly in
    proc/PID/maps' (bnc#1030901).

  - Revert 'RDMA/core: Fix incorrect structure packing for
    booleans' (kabi).

  - rtnetlink: allow to register ops without ops->setup set
    (bsc#1021374).

  - s390/zcrypt: Introduce CEX6 toleration (FATE#321783,
    LTC#147506, bsc#1019514).

  - sched/loadavg: Avoid loadavg spikes caused by delayed
    NO_HZ accounting (bsc#1018419).

  - scsi_error: count medium access timeout only once per EH
    run (bsc#993832, bsc#1032345).

  - scsi: libiscsi: add lock around task lists to fix list
    corruption regression (bsc#1034700).

  - scsi: storvsc: fix SRB_STATUS_ABORTED handling

  - sfc: reduce severity of PIO buffer alloc failures
    (bsc#1019168).

  - svcrpc: fix gss-proxy NULL dereference in some error
    cases (bsc#1024309).

  - taint/module: Clean up global and module taint flags
    handling

  - tcp: abort orphan sockets stalling on zero window probes
    (bsc#1021913).

  - thp: fix MADV_DONTNEED vs. numa balancing race
    (bnc#1027974).

  - thp: reduce indentation level in change_huge_pmd()
    (bnc#1027974).

  - treewide: fix 'distingush' typo (bsc#1020795).

  - tree-wide: use reinit_completion instead of
    INIT_COMPLETION (bsc#1020795).

  - usb: dwc3: gadget: Fix incorrect DEPCMD and DGCMD status
    macros (bsc#1035699).

  - usb: host: xhci: print correct command ring address
    (bnc#1035699).

  - USB: serial: kl5kusb105: fix line-state error handling
    (bsc#1021256).

  - vfs: Do not exchange 'short' filenames unconditionally
    (bsc#1012985).

  - vfs: split generic splice code from i_mutex locking
    (bsc#1024788).

  - vmxnet3: segCnt can be 1 for LRO packets (bsc#988065).

  - VSOCK: Detach QP check should filter out non matching
    QPs (bsc#1036752).

  - vxlan: cancel sock_work in vxlan_dellink()
    (bsc#1031567).

  - vxlan: Checksum fixes (bsc#1009682).

  - vxlan: GRO support at tunnel layer (bsc#1009682).

  - xen-blkfront: correct maximum segment accounting
    (bsc#1018263).

  - xen-blkfront: do not call talk_to_blkback when already
    connected to blkback.

  - xen-blkfront: free resources if xlvbd_alloc_gendisk
    fails.

  - xfs_dmapi: fix the debug compilation of xfs_dmapi
    (bsc#989056).

  - xfs: do not allow di_size with high bit set
    (bsc#1024234).

  - xfs: do not assert fail on non-async buffers on ioacct
    decrement (bsc#1024508).

  - xfs: exclude never-released buffers from buftarg I/O
    accounting (bsc#1024508).

  - xfs: fix broken multi-fsb buffer logging (bsc#1024081).

  - xfs: fix buffer overflow
    dm_get_dirattrs/dm_get_dirattrs2 (bsc#989056).

  - xfs: Fix lock ordering in splice write (bsc#1024788).

  - xfs: fix up xfs_swap_extent_forks inline extent handling
    (bsc#1023888).

  - xfs: Make xfs_icdinode->di_dmstate atomic_t
    (bsc#1024788).

  - xfs: pass total block res. as total xfs_bmapi_write()
    parameter (bsc#1029470).

  - xfs: replace global xfslogd wq with per-mount wq
    (bsc#1024508).

  - xfs: track and serialize in-flight async buffers against
    unmount (bsc#1024508).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1022559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1022971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1025039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1025235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1025354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1025802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1029470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1029850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1029986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1030118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1030213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1030593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1030901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1032125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1032141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1032344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1032345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1034670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/103470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1034700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1035576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1035699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1035738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1035877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1036752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1038261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/799133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/857926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1350.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10044.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10200.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10208.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2117.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3070.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5243.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7117.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9191.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9588.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9604.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2647.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2671.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5669.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5897.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5986.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6074.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6214.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6345.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6346.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6348.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6353.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6951.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7187.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7261.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7294.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7308.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7616.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7645.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8106.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171360-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f103bc6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1:zypper in -t patch
SUSE-SLE-WE-12-SP1-2017-831=1

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2017-831=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-831=1

SUSE Linux Enterprise Module for Public Cloud 12:zypper in -t patch
SUSE-SLE-Module-Public-Cloud-12-2017-831=1

SUSE Linux Enterprise Live Patching 12:zypper in -t patch
SUSE-SLE-Live-Patching-12-2017-831=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2017-831=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"kernel-default-man-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-debuginfo-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debuginfo-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debugsource-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-devel-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-syms-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-devel-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-syms-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.74-60.64.40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.74-60.64.40.1")) flag++;


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
