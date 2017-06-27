#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(76557);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/09/05 11:06:24 $");

  script_cve_id("CVE-2012-2372", "CVE-2013-2929", "CVE-2013-4299", "CVE-2013-4579", "CVE-2013-6382", "CVE-2013-7339", "CVE-2014-0055", "CVE-2014-0077", "CVE-2014-0101", "CVE-2014-0131", "CVE-2014-0155", "CVE-2014-1444", "CVE-2014-1445", "CVE-2014-1446", "CVE-2014-1874", "CVE-2014-2309", "CVE-2014-2523", "CVE-2014-2678", "CVE-2014-2851", "CVE-2014-3122", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3917", "CVE-2014-4508", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4699");

  script_name(english:"SuSE 11.3 Security Update : Linux kernel (SAT Patch Numbers 9488 / 9491 / 9493)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 3 kernel has been updated to
fix various bugs and security issues.

The following security bugs have been fixed :

  - The rds_ib_xmit function in net/rds/ib_send.c in the
    Reliable Datagram Sockets (RDS) protocol implementation
    in the Linux kernel 3.7.4 and earlier allows local users
    to cause a denial of service (BUG_ON and kernel panic)
    by establishing an RDS connection with the source IP
    address equal to the IPoIB interfaces own IP address, as
    demonstrated by rds-ping. (bnc#767610). (CVE-2012-2372)

  - The Linux kernel before 3.12.2 does not properly use the
    get_dumpable function, which allows local users to
    bypass intended ptrace restrictions or obtain sensitive
    information from IA64 scratch registers via a crafted
    application, related to kernel/ptrace.c and
    arch/ia64/include/asm/processor.h. (bnc#847652).
    (CVE-2013-2929)

  - Interpretation conflict in
    drivers/md/dm-snap-persistent.c in the Linux kernel
    through 3.11.6 allows remote authenticated users to
    obtain sensitive information or modify data via a
    crafted mapping to a snapshot block device.
    (bnc#846404). (CVE-2013-4299)

  - The ath9k_htc_set_bssid_mask function in
    drivers/net/wireless/ath/ath9k/htc_drv_main.c in the
    Linux kernel through 3.12 uses a BSSID masking approach
    to determine the set of MAC addresses on which a Wi-Fi
    device is listening, which allows remote attackers to
    discover the original MAC address after spoofing by
    sending a series of packets to MAC addresses with
    certain bit manipulations. (bnc#851426). (CVE-2013-4579)

  - Multiple buffer underflows in the XFS implementation in
    the Linux kernel through 3.12.1 allow local users to
    cause a denial of service (memory corruption) or
    possibly have unspecified other impact by leveraging the
    CAP_SYS_ADMIN capability for a (1)
    XFS_IOC_ATTRLIST_BY_HANDLE or (2)
    XFS_IOC_ATTRLIST_BY_HANDLE_32 ioctl call with a crafted
    length value, related to the xfs_attrlist_by_handle
    function in fs/xfs/xfs_ioctl.c and the
    xfs_compat_attrlist_by_handle function in
    fs/xfs/xfs_ioctl32.c. (bnc#852553). (CVE-2013-6382)

  - The rds_ib_laddr_check function in net/rds/ib.c in the
    Linux kernel before 3.12.8 allows local users to cause a
    denial of service (NULL pointer dereference and system
    crash) or possibly have unspecified other impact via a
    bind system call for an RDS socket on a system that
    lacks RDS transports. (bnc#869563). (CVE-2013-7339)

  - The get_rx_bufs function in drivers/vhost/net.c in the
    vhost-net subsystem in the Linux kernel package before
    2.6.32-431.11.2 on Red Hat Enterprise Linux (RHEL) 6
    does not properly handle vhost_get_vq_desc errors, which
    allows guest OS users to cause a denial of service (host
    OS crash) via unspecified vectors. (bnc#870173).
    (CVE-2014-0055)

  - drivers/vhost/net.c in the Linux kernel before 3.13.10,
    when mergeable buffers are disabled, does not properly
    validate packet lengths, which allows guest OS users to
    cause a denial of service (memory corruption and host OS
    crash) or possibly gain privileges on the host OS via
    crafted packets, related to the handle_rx and
    get_rx_bufs functions. (bnc#870576). (CVE-2014-0077)

  - The sctp_sf_do_5_1D_ce function in
    net/sctp/sm_statefuns.c in the Linux kernel through
    3.13.6 does not validate certain auth_enable and
    auth_capable fields before making an
    sctp_sf_authenticate call, which allows remote attackers
    to cause a denial of service (NULL pointer dereference
    and system crash) via an SCTP handshake with a modified
    INIT chunk and a crafted AUTH chunk before a COOKIE_ECHO
    chunk. (bnc#866102). (CVE-2014-0101)

  - Use-after-free vulnerability in the skb_segment function
    in net/core/skbuff.c in the Linux kernel through 3.13.6
    allows attackers to obtain sensitive information from
    kernel memory by leveraging the absence of a certain
    orphaning operation. (bnc#867723). (CVE-2014-0131)

  - The ioapic_deliver function in virt/kvm/ioapic.c in the
    Linux kernel through 3.14.1 does not properly validate
    the kvm_irq_delivery_to_apic return value, which allows
    guest OS users to cause a denial of service (host OS
    crash) via a crafted entry in the redirection table of
    an I/O APIC. NOTE: the affected code was moved to the
    ioapic_service function before the vulnerability was
    announced. (bnc#872540). (CVE-2014-0155)

  - The fst_get_iface function in drivers/net/wan/farsync.c
    in the Linux kernel before 3.11.7 does not properly
    initialize a certain data structure, which allows local
    users to obtain sensitive information from kernel memory
    by leveraging the CAP_NET_ADMIN capability for an
    SIOCWANDEV ioctl call. (bnc#858869). (CVE-2014-1444)

  - The wanxl_ioctl function in drivers/net/wan/wanxl.c in
    the Linux kernel before 3.11.7 does not properly
    initialize a certain data structure, which allows local
    users to obtain sensitive information from kernel memory
    via an ioctl call. (bnc#858870). (CVE-2014-1445)

  - The yam_ioctl function in drivers/net/hamradio/yam.c in
    the Linux kernel before 3.12.8 does not initialize a
    certain structure member, which allows local users to
    obtain sensitive information from kernel memory by
    leveraging the CAP_NET_ADMIN capability for an
    SIOCYAMGCFG ioctl call. (bnc#858872). (CVE-2014-1446)

  - The security_context_to_sid_core function in
    security/selinux/ss/services.c in the Linux kernel
    before 3.13.4 allows local users to cause a denial of
    service (system crash) by leveraging the CAP_MAC_ADMIN
    capability to set a zero-length security context.
    (bnc#863335). (CVE-2014-1874)

  - The ip6_route_add function in net/ipv6/route.c in the
    Linux kernel through 3.13.6 does not properly count the
    addition of routes, which allows remote attackers to
    cause a denial of service (memory consumption) via a
    flood of ICMPv6 Router Advertisement packets.
    (bnc#867531). (CVE-2014-2309)

  - net/netfilter/nf_conntrack_proto_dccp.c in the Linux
    kernel through 3.13.6 uses a DCCP header pointer
    incorrectly, which allows remote attackers to cause a
    denial of service (system crash) or possibly execute
    arbitrary code via a DCCP packet that triggers a call to
    the (1) dccp_new, (2) dccp_packet, or (3) dccp_error
    function. (bnc#868653). (CVE-2014-2523)

  - The rds_iw_laddr_check function in net/rds/iw.c in the
    Linux kernel through 3.14 allows local users to cause a
    denial of service (NULL pointer dereference and system
    crash) or possibly have unspecified other impact via a
    bind system call for an RDS socket on a system that
    lacks RDS transports. (bnc#871561). (CVE-2014-2678)

  - Integer overflow in the ping_init_sock function in
    net/ipv4/ping.c in the Linux kernel through 3.14.1
    allows local users to cause a denial of service
    (use-after-free and system crash) or possibly gain
    privileges via a crafted application that leverages an
    improperly managed reference counter. (bnc#873374).
    (CVE-2014-2851)

  - The try_to_unmap_cluster function in mm/rmap.c in the
    Linux kernel before 3.14.3 does not properly consider
    which pages must be locked, which allows local users to
    cause a denial of service (system crash) by triggering a
    memory-usage pattern that requires removal of page-table
    mappings. (bnc#876102). (CVE-2014-3122)

  - The (1) BPF_S_ANC_NLATTR and (2) BPF_S_ANC_NLATTR_NEST
    extension implementations in the sk_run_filter function
    in net/core/filter.c in the Linux kernel through 3.14.3
    do not check whether a certain length value is
    sufficiently large, which allows local users to cause a
    denial of service (integer underflow and system crash)
    via crafted BPF instructions. NOTE: the affected code
    was moved to the __skb_get_nlattr and
    __skb_get_nlattr_nest functions before the vulnerability
    was announced. (bnc#877257). (CVE-2014-3144)

  - The BPF_S_ANC_NLATTR_NEST extension implementation in
    the sk_run_filter function in net/core/filter.c in the
    Linux kernel through 3.14.3 uses the reverse order in a
    certain subtraction, which allows local users to cause a
    denial of service (over-read and system crash) via
    crafted BPF instructions. NOTE: the affected code was
    moved to the __skb_get_nlattr_nest function before the
    vulnerability was announced. (bnc#877257).
    (CVE-2014-3145)

  - kernel/auditsc.c in the Linux kernel through 3.14.5,
    when CONFIG_AUDITSYSCALL is enabled with certain syscall
    rules, allows local users to obtain potentially
    sensitive single-bit values from kernel memory or cause
    a denial of service (OOPS) via a large value of a
    syscall number. (bnc#880484). (CVE-2014-3917)

  - arch/x86/kernel/entry_32.S in the Linux kernel through
    3.15.1 on 32-bit x86 platforms, when syscall auditing is
    enabled and the sep CPU feature flag is set, allows
    local users to cause a denial of service (OOPS and
    system crash) via an invalid syscall number, as
    demonstrated by number. (CVE-2014-4508)

    -. (bnc#883724)

  - Race condition in the tlv handler functionality in the
    snd_ctl_elem_user_tlv function in sound/core/control.c
    in the ALSA control implementation in the Linux kernel
    before 3.15.2 allows local users to obtain sensitive
    information from kernel memory by leveraging
    /dev/snd/controlCX access. (bnc#883795). (CVE-2014-4652)

  - sound/core/control.c in the ALSA control implementation
    in the Linux kernel before 3.15.2 does not ensure
    possession of a read/write lock, which allows local
    users to cause a denial of service (use-after-free) and
    obtain sensitive information from kernel memory by
    leveraging /dev/snd/controlCX access. (bnc#883795).
    (CVE-2014-4653)

  - The snd_ctl_elem_add function in sound/core/control.c in
    the ALSA control implementation in the Linux kernel
    before 3.15.2 does not check authorization for
    SNDRV_CTL_IOCTL_ELEM_REPLACE commands, which allows
    local users to remove kernel controls and cause a denial
    of service (use-after-free and system crash) by
    leveraging /dev/snd/controlCX access for an ioctl call.
    (bnc#883795). (CVE-2014-4654)

  - The snd_ctl_elem_add function in sound/core/control.c in
    the ALSA control implementation in the Linux kernel
    before 3.15.2 does not properly maintain the
    user_ctl_count value, which allows local users to cause
    a denial of service (integer overflow and limit bypass)
    by leveraging /dev/snd/controlCX access for a large
    number of SNDRV_CTL_IOCTL_ELEM_REPLACE ioctl calls.
    (bnc#883795). (CVE-2014-4655)

  - Multiple integer overflows in sound/core/control.c in
    the ALSA control implementation in the Linux kernel
    before 3.15.2 allow local users to cause a denial of
    service by leveraging /dev/snd/controlCX access, related
    to (1) index values in the snd_ctl_add function and (2)
    numid values in the snd_ctl_remove_numid_conflict
    function. (bnc#883795). (CVE-2014-4656)

  - The Linux kernel before 3.15.4 on Intel processors does
    not properly restrict use of a non-canonical value for
    the saved RIP address in the case of a system call that
    does not use IRET, which allows local users to leverage
    a race condition and gain privileges, or cause a denial
    of service (double fault), via a crafted application
    that makes ptrace and fork system calls. (bnc#885725).
    (CVE-2014-4699)

Also the following non-security bugs have been fixed :

  - kernel: avoid page table walk on user space access
    (bnc#878407, LTC#110316).

  - spinlock: fix system hang with spin_retry <= 0
    (bnc#874145, LTC#110189).

  - x86/UV: Set n_lshift based on GAM_GR_CONFIG MMR for UV3.
    (bnc#876176)

  - x86: Enable multiple CPUs in crash kernel. (bnc#846690)

  - x86/mce: Fix CMCI preemption bugs. (bnc#786450)

  - x86, CMCI: Add proper detection of end of CMCI storms.
    (bnc#786450)

  - futex: revert back to the explicit waiter counting code.
    (bnc#851603)

  - futex: avoid race between requeue and wake. (bnc#851603)

  - intel-iommu: fix off-by-one in pagetable freeing.
    (bnc#874577)

  - ia64: Change default PSR.ac from '1' to '0' (Fix erratum
    #237). (bnc#874108)

  - drivers/rtc/interface.c: fix infinite loop in
    initializing the alarm. (bnc#871676)

  - drm/ast: Fix double lock at PM resume. (bnc#883380)

  - drm/ast: add widescreen + rb modes from X.org driver
    (v2). (bnc#883380)

  - drm/ast: deal with bo reserve fail in dirty update path.
    (bnc#883380)

  - drm/ast: do not attempt to acquire a reservation while
    in an interrupt handler. (bnc#883380)

  - drm/ast: fix the ast open key function. (bnc#883380)

  - drm/ast: fix value check in cbr_scan2. (bnc#883380)

  - drm/ast: inline reservations. (bnc#883380)

  - drm/ast: invalidate page tables when pinning a BO.
    (bnc#883380)

  - drm/ast: rename the mindwm/moutdwm and deinline them.
    (bnc#883380)

  - drm/ast: resync the dram post code with upstream.
    (bnc#883380)

  - drm: ast: use drm_can_sleep. (bnc#883380)

  - drm/ast: use drm_modeset_lock_all. (bnc#883380)

  - drm/: Unified handling of unimplemented
    fb->create_handle. (bnc#883380)

  - drm/mgag200,ast,cirrus: fix regression with
    drm_can_sleep conversion. (bnc#883380)

  - drm/mgag200: Consolidate depth/bpp handling.
    (bnc#882324)

  - drm/ast: Initialized data needed to map fbdev memory.
    (bnc#880007)

  - drm/ast: add AST 2400 support. (bnc#880007)

  - drm/ast: Initialized data needed to map fbdev memory.
    (bnc#880007)

  - drm/mgag200: on cards with < 2MB VRAM default to 16-bit.
    (bnc#882324)

  - drm/mgag200: fix typo causing bw limits to be ignored on
    some chips. (bnc#882324)

  - drm/ttm: do not oops if no invalidate_caches().
    (bnc#869414)

  - drm/i915: Break encoder->crtc link separately in
    intel_sanitize_crtc(). (bnc#855126)

  - dlm: keep listening connection alive with sctp mode.
    (bnc#881939)

  - series.conf: Clarify comment about Xen kabi adjustments
    (bnc#876114#c25)

  - btrfs: fix a crash when running balance and defrag
    concurrently.

  - btrfs: unset DCACHE_DISCONNECTED when mounting default
    subvol. (bnc#866615)

  - btrfs: free delayed node outside of root->inode_lock.
    (bnc#866864)

  - btrfs: return EPERM when deleting a default subvolume.
    (bnc#869934)

  - btrfs: do not loop on large offsets in readdir.
    (bnc#863300)

  - sched: Consider pi boosting in setscheduler.

  - sched: Queue RT tasks to head when prio drops.

  - sched: Adjust sched_reset_on_fork when nothing else
    changes.

  - sched: Fix clock_gettime(CLOCK__CPUTIME_ID)
    monotonicity. (bnc#880357)

  - sched: Do not allow scheduler time to go backwards.
    (bnc#880357)

  - sched: Make scale_rt_power() deal with backward clocks.
    (bnc#865310)

  - sched: Use CPUPRI_NR_PRIORITIES instead of MAX_RT_PRIO
    in cpupri check. (bnc#871861)

  - sched: update_rq_clock() must skip ONE update.
    (bnc#869033, bnc#868528)

  - tcp: allow to disable cwnd moderation in TCP_CA_Loss
    state. (bnc#879921)

  - tcp: clear xmit timers in tcp_v4_syn_recv_sock().
    (bnc#862429)

  - net: add missing bh_unlock_sock() calls. (bnc#862429)

  - bonding: fix vlan_features computing. (bnc#872634)

  - vlan: more careful checksum features handling.
    (bnc#872634)

  - xfrm: fix race between netns cleanup and state expire
    notification. (bnc#879957)

  - xfrm: check peer pointer for null before calling
    inet_putpeer(). (bnc#877775)

  - ipv6: do not overwrite inetpeer metrics prematurely.
    (bnc#867362)

  - pagecachelimit: reduce lru_lock contention for heavy
    parallel kabi fixup:. (bnc#878509, bnc#864464)

  - pagecachelimit: reduce lru_lock contention for heavy
    parallel reclaim. (bnc#878509, bnc#864464)

  - TTY: serial, cleanup include file. (bnc#881571)

  - TTY: serial, fix includes in some drivers. (bnc#881571)

  - serial_core: Fix race in uart_handle_dcd_change.
    (bnc#881571)

  - powerpc/perf: Power8 PMU support. (bnc#832710)

  - powerpc/perf: Add support for SIER. (bnc#832710)

  - powerpc/perf: Add regs_no_sipr(). (bnc#832710)

  - powerpc/perf: Add an accessor for regs->result.
    (bnc#832710)

  - powerpc/perf: Convert mmcra_sipr/sihv() to
    regs_sipr/sihv(). (bnc#832710)

  - powerpc/perf: Add an explict flag indicating presence of
    SLOT field. (bnc#832710)

  - swiotlb: do not assume PA 0 is invalid. (bnc#865882)

  - lockref: implement lockless reference count updates
    using cmpxchg() (FATE#317271).

  - af_iucv: wrong mapping of sent and confirmed skbs
    (bnc#878407, LTC#110452).

  - af_iucv: recvmsg problem for SOCK_STREAM sockets
    (bnc#878407, LTC#110452).

  - af_iucv: fix recvmsg by replacing skb_pull() function
    (bnc#878407, LTC#110452).

  - qla2xxx: Poll during initialization for ISP25xx and
    ISP83xx. (bnc#837563)

  - qla2xxx: Fix request queue null dereference.
    (bnc#859840)

  - lpfc 8.3.41: Fixed SLI3 failing FCP write on
    check-condition no-sense with residual zero.
    (bnc#850915)

  - reiserfs: call truncate_setsize under tailpack mutex.
    (bnc#878115)

  - reiserfs: drop vmtruncate. (bnc#878115)

  - ipvs: handle IPv6 fragments with one-packet scheduling.
    (bnc#861980)

  - kabi: hide modifications of struct sk_buff done by
    bnc#861980 fix. (bnc#861980)

  - loop: remove the incorrect write_begin/write_end
    shortcut. (bnc#878123)

  - watchdog: hpwdt patch to display informative string.
    (bnc#862934)

  - watchdog: hpwdt: Patch to ignore auxilary iLO devices.
    (bnc#862934)

  - watchdog: hpwdt: Add check for UEFI bits. (bnc#862934)

  - watchdog: hpwdt.c: Increase version string. (bnc#862934)

  - hpilo: Correct panic when an AUX iLO is detected.
    (bnc#837563)

  - locking/mutexes: Introduce cancelable MCS lock for
    adaptive spinning (FATE#317271).

  - locking/mutexes: Modify the way optimistic spinners are
    queued (FATE#317271).

  - locking/mutexes: Return false if task need_resched() in
    mutex_can_spin_on_owner() (FATE#317271).

  - mutex: Enable the queuing of mutex spinners with MCS
    lock (FATE#317271). config: disabled on all flavors

  - mutex: Queue mutex spinners with MCS lock to reduce
    cacheline contention (FATE#317271).

  - memcg: deprecate memory.force_empty knob. (bnc#878274)

  - kabi: protect struct net from bnc#877013 changes.
    (bnc#877013)

  - netfilter: nfnetlink_queue: add net namespace support
    for nfnetlink_queue. (bnc#877013)

  - netfilter: make /proc/net/netfilter pernet. (bnc#877013)

  - netfilter: xt_hashlimit: fix proc entry leak in netns
    destroy path. (bnc#871634)

  - netfilter: xt_hashlimit: fix namespace destroy path.
    (bnc#871634)

  - netfilter: nf_queue: reject NF_STOLEN verdicts from
    userspace. (bnc#870877)

  - netfilter: avoid double free in nf_reinject.
    (bnc#870877)

  - netfilter: ctnetlink: fix race between delete and
    timeout expiration. (bnc#863410)

  - netfilter: reuse skb->nfct_reasm for ipvs conn
    reference. (bnc#861980)

  - mm: per-thread vma caching (FATE#317271). config: enable
    CONFIG_VMA_CACHE for x86_64/bigsmp

  - mm, hugetlb: improve page-fault scalability
    (FATE#317271).

  - mm: vmscan: Do not throttle based on pfmemalloc reserves
    if node has no ZONE_NORMAL. (bnc#870496)

  - mm: fix off-by-one bug in print_nodes_state().
    (bnc#792271)

  - hugetlb: ensure hugepage access is denied if hugepages
    are not supported (PowerKVM crash when mounting
    hugetlbfs without hugepage support (bnc#870498)).

  - SELinux: Increase ebitmap_node size for 64-bit
    configuration (FATE#317271).

  - SELinux: Reduce overhead of mls_level_isvalid() function
    call (FATE#317271).

  - mutex: Fix debug_mutexes (FATE#317271).

  - mutex: Fix debug checks (FATE#317271).

  - locking/mutexes: Unlock the mutex without the wait_lock
    (FATE#317271).

  - epoll: do not take the nested ep->mtx on EPOLL_CTL_DEL
    (FATE#317271).

  - epoll: do not take global 'epmutex' for simple
    topologies (FATE#317271).

  - epoll: optimize EPOLL_CTL_DEL using rcu (FATE#317271).

  - vfs: Fix missing unlock of vfsmount_lock in unlazy_walk.
    (bnc#880437)

  - dcache: kABI fixes for lockref dentries (FATE#317271).

  - vfs: make sure we do not have a stale root path if
    unlazy_walk() fails (FATE#317271).

  - vfs: fix dentry RCU to refcounting possibly sleeping
    dput() (FATE#317271).

  - vfs: use lockref 'dead' flag to mark unrecoverably dead
    dentries (FATE#317271).

  - vfs: reimplement d_rcu_to_refcount() using
    lockref_get_or_lock() (FATE#317271).

  - vfs: Remove second variable named error in __dentry_path
    (FATE#317271).

  - make prepend_name() work correctly when called with
    negative *buflen (FATE#317271).

  - prepend_path() needs to reinitialize dentry/vfsmount on
    restarts (FATE#317271).

  - dcache: get/release read lock in read_seqbegin_or_lock()
    &amp; friend (FATE#317271).

  - seqlock: Add a new locking reader type (FATE#317271).

  - dcache: Translating dentry into pathname without taking
    rename_lock (FATE#317271).

  - vfs: make the dentry cache use the lockref
    infrastructure (FATE#317271).

  - vfs: Remove dentry->d_lock locking from
    shrink_dcache_for_umount_subtree() (FATE#317271).

  - vfs: use lockref_get_not_zero() for optimistic lockless
    dget_parent() (FATE#317271).

  - vfs: constify dentry parameter in d_count()
    (FATE#317271).

  - helper for reading ->d_count (FATE#317271).

  - lockref: use arch_mutex_cpu_relax() in CMPXCHG_LOOP()
    (FATE#317271).

  - lockref: allow relaxed cmpxchg64 variant for lockless
    updates (FATE#317271).

  - lockref: use cmpxchg64 explicitly for lockless updates
    (FATE#317271).

  - lockref: add ability to mark lockrefs 'dead'
    (FATE#317271).

  - lockref: fix docbook argument names (FATE#317271).

  - lockref: Relax in cmpxchg loop (FATE#317271).

  - lockref: implement lockless reference count updates
    using cmpxchg() (FATE#317271).

  - lockref: uninline lockref helper functions
    (FATE#317271).

  - lockref: add lockref_get_or_lock() helper (FATE#317271).

  - Add new lockref infrastructure reference implementation
    (FATE#317271).

  - vfs: make lremovexattr retry once on ESTALE error.
    (bnc#876463)

  - vfs: make removexattr retry once on ESTALE. (bnc#876463)

  - vfs: make llistxattr retry once on ESTALE error.
    (bnc#876463)

  - vfs: make listxattr retry once on ESTALE error.
    (bnc#876463)

  - vfs: make lgetxattr retry once on ESTALE. (bnc#876463)

  - vfs: make getxattr retry once on an ESTALE error.
    (bnc#876463)

  - vfs: allow lsetxattr() to retry once on ESTALE errors.
    (bnc#876463)

  - vfs: allow setxattr to retry once on ESTALE errors.
    (bnc#876463)

  - vfs: allow utimensat() calls to retry once on an ESTALE
    error. (bnc#876463)

  - vfs: fix user_statfs to retry once on ESTALE errors.
    (bnc#876463)

  - vfs: make fchownat retry once on ESTALE errors.
    (bnc#876463)

  - vfs: make fchmodat retry once on ESTALE errors.
    (bnc#876463)

  - vfs: have chroot retry once on ESTALE error.
    (bnc#876463)

  - vfs: have chdir retry lookup and call once on ESTALE
    error. (bnc#876463)

  - vfs: have faccessat retry once on an ESTALE error.
    (bnc#876463)

  - vfs: have do_sys_truncate retry once on an ESTALE error.
    (bnc#876463)

  - vfs: fix renameat to retry on ESTALE errors.
    (bnc#876463)

  - vfs: make do_unlinkat retry once on ESTALE errors.
    (bnc#876463)

  - vfs: make do_rmdir retry once on ESTALE errors.
    (bnc#876463)

  - vfs: fix linkat to retry once on ESTALE errors.
    (bnc#876463)

  - vfs: fix symlinkat to retry on ESTALE errors.
    (bnc#876463)

  - vfs: fix mkdirat to retry once on an ESTALE error.
    (bnc#876463)

  - vfs: fix mknodat to retry on ESTALE errors. (bnc#876463)

  - vfs: add a flags argument to user_path_parent.
    (bnc#876463)

  - vfs: fix readlinkat to retry on ESTALE. (bnc#876463)

  - vfs: make fstatat retry on ESTALE errors from getattr
    call. (bnc#876463)

  - vfs: add a retry_estale helper function to handle
    retries on ESTALE. (bnc#876463)

  - crypto: s390 - fix aes,des ctr mode concurrency finding
    (bnc#874145, LTC#110078).

  - s390/cio: fix unlocked access of global bitmap
    (bnc#874145, LTC#109378).

  - s390/css: stop stsch loop after cc 3 (bnc#874145,
    LTC#109378).

  - s390/pci: add kmsg man page (bnc#874145, LTC#109224).

  - s390/pci/dma: use correct segment boundary size
    (bnc#866081, LTC#104566).

  - cio: Fix missing subchannels after CHPID configure on
    (bnc#866081, LTC#104808).

  - cio: Fix process hangs during subchannel scan
    (bnc#866081, LTC#104805).

  - cio: fix unusable device (bnc#866081, LTC#104168).

  - qeth: postpone freeing of qdio memory (bnc#874145,
    LTC#107873).

  - Fix race between starved list and device removal.
    (bnc#861636)

  - namei.h: include errno.h. (bnc#876463)

  - ALSA: hda - Implement bind mixer ctls for Conexant.
    (bnc#872188)

  - ALSA: hda - Fix invalid Auto-Mute Mode enum from cxt
    codecs. (bnc#872188)

  - ALSA: hda - Fix conflicting Capture Source on cxt
    codecs. (bnc#872188)

  - ALSA: usb-audio: Fix NULL dereference while quick
    replugging. (bnc#870335)

  - powerpc: Bring all threads online prior to
    migration/hibernation. (bnc#870591)

  - powerpc/pseries: Update dynamic cache nodes for
    suspend/resume operation. (bnc#873463)

  - powerpc/pseries: Device tree should only be updated once
    after suspend/migrate. (bnc#873463)

  - powerpc/pseries: Expose in kernel device tree update to
    drmgr. (bnc#873463)

  - powerpc: Add second POWER8 PVR entry. (bnc#874440)

  - libata/ahci: accommodate tag ordered controllers.
    (bnc#871728)

  - md: try to remove cause of a spinning md thread.
    (bnc#875386)

  - md: fix up plugging (again). (bnc#866800)

  - NFSv4: Fix a reboot recovery race when opening a file.
    (bnc#864404)

  - NFSv4: Ensure delegation recall and byte range lock
    removal do not conflict. (bnc#864404)

  - NFSv4: Fix up the return values of
    nfs4_open_delegation_recall. (bnc#864404)

  - NFSv4.1: Do not lose locks when a server reboots during
    delegation return. (bnc#864404)

  - NFSv4.1: Prevent deadlocks between state recovery and
    file locking. (bnc#864404)

  - NFSv4: Allow the state manager to mark an open_owner as
    being recovered. (bnc#864404)

  - NFS: nfs_inode_return_delegation() should always flush
    dirty data. (bnc#864404)

  - NFSv4: nfs_client_return_marked_delegations cannot flush
    data. (bnc#864404)

  - NFS: avoid excessive GETATTR request when attributes
    expired but cached directory is valid. (bnc#857926)

  - seqlock: add 'raw_seqcount_begin()' function.
    (bnc#864404)

  - Allow nfsdv4 to work when fips=1. (bnc#868488)

  - NFSv4: Add ACCESS operation to OPEN compound.
    (bnc#870958)

  - NFSv4: Fix unnecessary delegation returns in
    nfs4_do_open. (bnc#870958)

  - NFSv4: The NFSv4.0 client must send RENEW calls if it
    holds a delegation. (bnc#863873)

  - NFSv4: nfs4_proc_renew should be declared static.
    (bnc#863873)

  - NFSv4: do not put ACCESS in OPEN compound if O_EXCL.
    (bnc#870958)

  - NFS: revalidate on open if dcache is negative.
    (bnc#876463)

  - NFSD add module parameter to disable delegations.
    (bnc#876463)

  - Do not lose sockets when nfsd shutdown races with
    connection timeout. (bnc#871854)

  - timer: Prevent overflow in apply_slack. (bnc#873061)

  - mei: me: do not load the driver if the FW does not
    support MEI interface. (bnc#821619)

  - ipmi: Reset the KCS timeout when starting error
    recovery. (bnc#870618)

  - ipmi: Fix a race restarting the timer. (bnc#870618)

  - ipmi: increase KCS timeouts. (bnc#870618)

  - bnx2x: Fix kernel crash and data miscompare after EEH
    recovery. (bnc#881761)

  - bnx2x: Adapter not recovery from EEH error injection.
    (bnc#881761)

  - kabi: hide modifications of struct inet_peer done by
    bnc#867953 fix. (bnc#867953)

  - inetpeer: prevent unlinking from unused list twice.
    (bnc#867953)

  - Ignore selected taints for tracepoint modules
    (bnc#870450, FATE#317134).

  - Use 'E' instead of 'X' for unsigned module taint flag
    (bnc#870450,FATE#317134).

  - Fix: module signature vs tracepoints: add new
    TAINT_UNSIGNED_MODULE (bnc#870450,FATE#317134).

  - xhci: extend quirk for Renesas cards. (bnc#877497)

  - scsi: return target failure on EMC inactive snapshot.
    (bnc#840524)

  - virtio_balloon: do not softlockup on huge balloon
    changes. (bnc#871899)

  - ch: add refcounting. (bnc#867517)

  - storvsc: NULL pointer dereference fix. (bnc#865330)

  - Unlock the rename_lock in dentry_path() in the case when
    path is too long. (bnc#868748)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=767610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=832710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=837563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=846404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=846690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=847652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=850915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=851426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=851603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=855126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=857926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=858869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=858870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=858872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=859840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=861636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=861980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=862429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=862934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=866081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=866102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=866615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=866800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=866864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=867362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=867517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=867531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=867723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=867953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=868488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=868528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=868653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=868748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=869033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=869414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=869563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=869934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=870173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=870335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=870450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=870496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=870498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=870576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=870591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=870618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=870877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=870958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=872188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=872540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=872634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=873061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=873374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=873463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=874108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=874145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=874440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=874577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=875386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=876102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=876114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=876176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=876463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=877013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=877257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=877497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=877775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=878115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=878123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=878274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=878407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=878509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=879921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=879957"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=880007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=880357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=880437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=880484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=881571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=881761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=881939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=882324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=883380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=883795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=885725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2372.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2929.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4299.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4579.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6382.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7339.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0055.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0101.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0131.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0155.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1444.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1445.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1874.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2309.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2523.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2678.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2851.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3122.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3144.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3145.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3917.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4508.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4652.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4653.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4654.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4655.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4656.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4699.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 9488 / 9491 / 9493 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-base-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-devel-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-extra-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-base-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-extra-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-source-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-syms-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-trace-devel-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-base-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-extra-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-kmp-default-4.2.4_02_3.0.101_0.35-0.7.45")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-kmp-pae-4.2.4_02_3.0.101_0.35-0.7.45")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-base-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-devel-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-extra-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-source-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-syms-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.4_02_3.0.101_0.35-0.7.45")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-base-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-devel-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-source-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-syms-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-base-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-devel-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-base-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-base-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-kmp-default-4.2.4_02_3.0.101_0.35-0.7.45")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-kmp-pae-4.2.4_02_3.0.101_0.35-0.7.45")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"kernel-default-man-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.4_02_3.0.101_0.35-0.7.45")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
