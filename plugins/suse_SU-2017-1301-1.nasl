#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1301-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(100214);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/16 13:59:27 $");

  script_cve_id("CVE-2015-3288", "CVE-2015-8970", "CVE-2016-10200", "CVE-2016-5243", "CVE-2017-2671", "CVE-2017-5669", "CVE-2017-5970", "CVE-2017-5986", "CVE-2017-6074", "CVE-2017-6214", "CVE-2017-6348", "CVE-2017-6353", "CVE-2017-7184", "CVE-2017-7187", "CVE-2017-7261", "CVE-2017-7294", "CVE-2017-7308", "CVE-2017-7616");
  script_osvdb_id(139499, 142044, 146704, 151927, 152094, 152302, 152453, 152521, 152685, 152709, 153065, 153853, 154043, 154359, 154384, 154548, 154633, 155190);

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2017:1301-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various
security and bugfixes. Notable new features :

  - Toleration of newer crypto hardware for z Systems

  - USB 2.0 Link power management for Haswell-ULT The
    following security bugs were fixed :

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

  - CVE-2017-7184: The xfrm_replay_verify_len function in
    net/xfrm/xfrm_user.c in the Linux kernel did not
    validate certain size data after an XFRM_MSG_NEWAE
    update, which allowed local users to obtain root
    privileges or cause a denial of service (heap-based
    out-of-bounds access) by leveraging the CAP_NET_ADMIN
    capability (bsc#1030573).

  - CVE-2017-5970: The ipv4_pktinfo_prepare function in
    net/ipv4/ip_sockglue.c in the Linux kernel allowed
    attackers to cause a denial of service (system crash)
    via (1) an application that made crafted system calls or
    possibly (2) IPv4 traffic with invalid IP options
    (bsc#1024938).

  - CVE-2017-7616: Incorrect error handling in the
    set_mempolicy and mbind compat syscalls in
    mm/mempolicy.c in the Linux kernel allowed local users
    to obtain sensitive information from uninitialized stack
    data by triggering failure of a certain bitmap operation
    (bsc#1033336).

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

  - CVE-2017-6348: The hashbin_delete function in
    net/irda/irqueue.c in the Linux kernel improperly
    managed lock dropping, which allowed local users to
    cause a denial of service (deadlock) via crafted
    operations on IrDA devices (bnc#1027178)

  - CVE-2017-5669: The do_shmat function in ipc/shm.c in the
    Linux kernel did not restrict the address calculated by
    a certain rounding operation, which allowed local users
    to map page zero, and consequently bypass a protection
    mechanism that exists for the mmap system call, by
    making crafted shmget and shmat system calls in a
    privileged context (bnc#1026914)

  - CVE-2015-3288: mm/memory.c in the Linux kernel
    mishandled anonymous pages, which allowed local users to
    gain privileges or cause a denial of service (page
    tainting) via a crafted application that triggers
    writing to page zero (bsc#979021).

  - CVE-2016-10200: Race condition in the L2TPv3 IP
    Encapsulation feature in the Linux kernel allowed local
    users to gain privileges or cause a denial of service
    (use-after-free) by making multiple bind system calls
    without properly ascertaining whether a socket has the
    SOCK_ZAPPED status, related to net/l2tp/l2tp_ip.c and
    net/l2tp/l2tp_ip6.c (bnc#1028415)

  - CVE-2016-5243: The tipc_nl_compat_link_dump function in
    net/tipc/netlink_compat.c in the Linux kernel did not
    properly copy a certain string, which allowed local
    users to obtain sensitive information from kernel stack
    memory by reading a Netlink message (bnc#983212)

  - CVE-2017-6353: net/sctp/socket.c in the Linux kernel did
    not properly restrict association peel-off operations
    during certain wait states, which allowed local users to
    cause a denial of service (invalid unlock and double
    free) via a multithreaded application (bnc#1027066)

  - CVE-2017-6214: The tcp_splice_read function in
    net/ipv4/tcp.c in the Linux kernel allowed remote
    attackers to cause a denial of service (infinite loop
    and soft lockup) via vectors involving a TCP packet with
    the URG flag (bnc#1026722)

  - CVE-2017-6074: The dccp_rcv_state_process function in
    net/dccp/input.c in the Linux kernel mishandled
    DCCP_PKT_REQUEST packet data structures in the LISTEN
    state, which allowed local users to obtain root
    privileges or cause a denial of service (double free)
    via an application that made an IPV6_RECVPKTINFO
    setsockopt system call (bnc#1026024)

  - CVE-2017-5986: Race condition in the
    sctp_wait_for_sndbuf function in net/sctp/socket.c in
    the Linux kernel allowed local users to cause a denial
    of service (assertion failure and panic) via a
    multithreaded application that peels off an association
    in a certain buffer-full state (bsc#1025235)

  - CVE-2015-8970: crypto/algif_skcipher.c in the Linux
    kernel did not verify that a setkey operation has been
    performed on an AF_ALG socket an accept system call is
    processed, which allowed local users to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted application that does not supply a key,
    related to the lrw_crypt function in crypto/lrw.c
    (bsc#1008374). The following non-security bugs were
    fixed :

  - NFSD: do not risk using duplicate owner/file/delegation
    ids (bsc#1029212).

  - RAID1: avoid unnecessary spin locks in I/O barrier code
    (bsc#982783, bsc#1026260).

  - SUNRPC: Clean up the slot table allocation
    (bsc#1013862).

  - SUNRPC: Initalise the struct xprt upon allocation
    (bsc#1013862).

  - USB: cdc-acm: fix broken runtime suspend (bsc#1033771).

  - USB: cdc-acm: fix open and suspend race (bsc#1033771).

  - USB: cdc-acm: fix potential urb leak and PM imbalance in
    write (bsc#1033771).

  - USB: cdc-acm: fix runtime PM for control messages
    (bsc#1033771).

  - USB: cdc-acm: fix runtime PM imbalance at shutdown
    (bsc#1033771).

  - USB: cdc-acm: fix shutdown and suspend race
    (bsc#1033771).

  - USB: cdc-acm: fix write and resume race (bsc#1033771).

  - USB: cdc-acm: fix write and suspend race (bsc#1033771).

  - USB: hub: Fix crash after failure to read BOS descriptor

  - USB: serial: iuu_phoenix: fix NULL-deref at open
    (bsc#1033794).

  - USB: serial: kl5kusb105: fix line-state error handling
    (bsc#1021256).

  - USB: serial: mos7720: fix NULL-deref at open
    (bsc#1033816).

  - USB: serial: mos7720: fix parallel probe (bsc#1033816).

  - USB: serial: mos7720: fix parport use-after-free on
    probe errors (bsc#1033816).

  - USB: serial: mos7720: fix use-after-free on probe errors
    (bsc#1033816).

  - USB: serial: mos7840: fix NULL-deref at open
    (bsc#1034026).

  - USB: xhci-mem: use passed in GFP flags instead of
    GFP_KERNEL (bsc#1023014).

  - Update metadata for serial fixes (bsc#1013070)

  - Use PF_LESS_THROTTLE in loop device thread
    (bsc#1027101).

  - clocksource: Remove 'weak' from
    clocksource_default_clock() declaration (bnc#1013018).

  - dlm: backport 'fix lvb invalidation conditions'
    (bsc#1005651).

  - drm/mgag200: Add support for G200e rev 4 (bnc#995542,
    comment #81)

  - enic: set skb->hash type properly (bsc#911105).

  - ext4: fix mballoc breakage with 64k block size
    (bsc#1013018).

  - ext4: fix stack memory corruption with 64k block size
    (bsc#1013018).

  - ext4: reject inodes with negative size (bsc#1013018).

  - fuse: initialize fc->release before calling it
    (bsc#1013018).

  - i40e/i40evf: Break up xmit_descriptor_count from
    maybe_stop_tx (bsc#985561).

  - i40e/i40evf: Fix mixed size frags and linearization
    (bsc#985561).

  - i40e/i40evf: Limit TSO to 7 descriptors for payload
    instead of 8 per packet (bsc#985561).

  - i40e/i40evf: Rewrite logic for 8 descriptor per packet
    check (bsc#985561).

  - i40e: Fix TSO with more than 8 frags per segment issue
    (bsc#985561).

  - i40e: Impose a lower limit on gso size (bsc#985561).

  - i40e: Limit TX descriptor count in cases where frag size
    is greater than 16K (bsc#985561).

  - i40e: avoid NULL pointer dereference (bsc#909486).

  - jbd: Fix oops in journal_remove_journal_head()
    (bsc#1017143).

  - jbd: do not wait (forever) for stale tid caused by
    wraparound (bsc#1020229).

  - kABI: mask struct xfs_icdinode change (bsc#1024788).

  - kabi: Protect xfs_mount and xfs_buftarg (bsc#1024508).

  - kabi: fix (bsc#1008893).

  - lockd: use init_utsname for id encoding (bsc#1033804).

  - lockd: use rpc client's cl_nodename for id encoding
    (bsc#1033804).

  - md linear: fix a race between linear_add() and
    linear_congested() (bsc#1018446).

  - md/linear: shutup lockdep warnning (bsc#1018446).

  - mm/mempolicy.c: do not put mempolicy before using its
    nodemask (bnc#931620).

  - ocfs2: do not write error flag to user structure we
    cannot copy from/to (bsc#1013018).

  - ocfs2: fix crash caused by stale lvb with fsdlm plugin
    (bsc#1013800).

  - ocfs2: fix error return code in
    ocfs2_info_handle_freefrag() (bsc#1013018).

  - ocfs2: null deref on allocation error (bsc#1013018).

  - pciback: only check PF if actually dealing with a VF
    (bsc#999245).

  - pciback: use pci_physfn() (bsc#999245).

  - posix-timers: Fix stack info leak in timer_create()
    (bnc#1013018).

  - powerpc,cpuidle: Dont toggle CPUIDLE_FLAG_IGNORE while
    setting smt_snooze_delay (bsc#1023163).

  - powerpc/fadump: Fix the race in crash_fadump()
    (bsc#1022971).

  - powerpc/fadump: Reserve memory at an offset closer to
    bottom of RAM (bsc#1032141).

  - powerpc/fadump: Update fadump documentation
    (bsc#1032141).

  - powerpc/nvram: Fix an incorrect partition merge
    (bsc#1016489).

  - powerpc/vdso64: Use double word compare on pointers
    (bsc#1016489).

  - rcu: Call out dangers of expedited RCU primitives
    (bsc#1008893).

  - rcu: Direct algorithmic SRCU implementation
    (bsc#1008893).

  - rcu: Flip ->completed only once per SRCU grace period
    (bsc#1008893).

  - rcu: Implement a variant of Peter's SRCU algorithm
    (bsc#1008893).

  - rcu: Increment upper bit only for srcu_read_lock()
    (bsc#1008893).

  - rcu: Remove fast check path from __synchronize_srcu()
    (bsc#1008893).

  - s390/kmsg: add missing kmsg descriptions (bnc#1025702).

  - s390/vmlogrdr: fix IUCV buffer allocation (bnc#1025702).

  - s390/zcrypt: Introduce CEX6 toleration

  - sched/core: Fix TASK_DEAD race in finish_task_switch()
    (bnc#1013018).

  - sched/loadavg: Fix loadavg artifacts on fully idle and
    on fully loaded systems (bnc#1013018).

  - scsi: zfcp: do not trace pure benign residual HBA
    responses at default level (bnc#1025702).

  - scsi: zfcp: fix rport unblock race with LUN recovery
    (bnc#1025702).

  - scsi: zfcp: fix use-after-'free' in FC ingress path
    after TMF (bnc#1025702).

  - scsi: zfcp: fix use-after-free by not tracing WKA port
    open/close on failed send (bnc#1025702).

  - sfc: reduce severity of PIO buffer alloc failures
    (bsc#1019168).

  - tcp: abort orphan sockets stalling on zero window probes
    (bsc#1021913).

  - vfs: split generic splice code from i_mutex locking
    (bsc#1024788).

  - virtio_scsi: fix memory leak on full queue condition
    (bsc#1028880).

  - vmxnet3: segCnt can be 1 for LRO packets (bsc#988065,
    bsc#1029770).

  - xen-blkfront: correct maximum segment accounting
    (bsc#1018263).

  - xen-blkfront: do not call talk_to_blkback when already
    connected to blkback.

  - xen-blkfront: free resources if xlvbd_alloc_gendisk
    fails.

  - xfs: Fix lock ordering in splice write (bsc#1024788).

  - xfs: Make xfs_icdinode->di_dmstate atomic_t
    (bsc#1024788).

  - xfs: do not assert fail on non-async buffers on ioacct
    decrement (bsc#1024508).

  - xfs: exclude never-released buffers from buftarg I/O
    accounting (bsc#1024508).

  - xfs: fix buffer overflow
    dm_get_dirattrs/dm_get_dirattrs2 (bsc#989056).

  - xfs: fix up xfs_swap_extent_forks inline extent handling
    (bsc#1023888).

  - xfs: kill xfs_itruncate_start (bsc#1024788).

  - xfs: remove the i_new_size field in struct xfs_inode
    (bsc#1024788).

  - xfs: remove the i_size field in struct xfs_inode
    (bsc#1024788).

  - xfs: remove xfs_itruncate_data (bsc#1024788).

  - xfs: replace global xfslogd wq with per-mount wq
    (bsc#1024508).

  - xfs: split xfs_itruncate_finish (bsc#1024788).

  - xfs: split xfs_setattr (bsc#1024788).

  - xfs: track and serialize in-flight async buffers against
    unmount (bsc#1024508).

  - xfs_dmapi: fix the debug compilation of xfs_dmapi
    (bsc#989056).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1016489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018263"
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
    value:"https://bugzilla.suse.com/1020229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1022971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023888"
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
    value:"https://bugzilla.suse.com/1024938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1025235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1025702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026260"
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
    value:"https://bugzilla.suse.com/1027101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1029212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1029770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1030213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1030573"
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
    value:"https://bugzilla.suse.com/1031440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1032141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033816"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1034026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/911105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979021"
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
    value:"https://bugzilla.suse.com/995542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3288.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8970.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10200.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5243.html"
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
    value:"https://www.suse.com/security/cve/CVE-2017-5970.html"
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
    value:"https://www.suse.com/security/cve/CVE-2017-6348.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6353.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7184.html"
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
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171301-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f85e29f0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-linux-kernel-13105=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-linux-kernel-13105=1

SUSE Linux Enterprise Server 11-EXTRA:zypper in -t patch
slexsp3-linux-kernel-13105=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-linux-kernel-13105=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/16");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"kernel-default-man-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-base-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-devel-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-source-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-syms-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-base-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-devel-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-base-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-base-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-devel-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-base-3.0.101-100.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-devel-3.0.101-100.1")) flag++;


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
