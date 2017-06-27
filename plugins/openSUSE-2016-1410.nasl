#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1410.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95592);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/07 14:54:25 $");

  script_cve_id("CVE-2013-5634", "CVE-2015-8956", "CVE-2016-2069", "CVE-2016-5696", "CVE-2016-6130", "CVE-2016-6327", "CVE-2016-6480", "CVE-2016-6828", "CVE-2016-7042", "CVE-2016-7097", "CVE-2016-7425", "CVE-2016-8658");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2016-1410)");
  script_summary(english:"Check for the openSUSE-2016-1410 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 13.1 kernel was updated to 3.12.67 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2013-5634: arch/arm/kvm/arm.c in the Linux kernel on
    the ARM platform, when KVM is used, allowed host OS
    users to cause a denial of service (NULL pointer
    dereference, OOPS, and host OS crash) or possibly have
    unspecified other impact by omitting vCPU initialization
    before a KVM_GET_REG_LIST ioctl call. (bsc#994758)

  - CVE-2016-2069: Race condition in arch/x86/mm/tlb.c in
    the Linux kernel allowed local users to gain privileges
    by triggering access to a paging structure by a
    different CPU (bnc#963767).

  - CVE-2016-7042: The proc_keys_show function in
    security/keys/proc.c in the Linux kernel used an
    incorrect buffer size for certain timeout data, which
    allowed local users to cause a denial of service (stack
    memory corruption and panic) by reading the /proc/keys
    file (bnc#1004517).

  - CVE-2016-7097: The filesystem implementation in the
    Linux kernel preserved the setgid bit during a setxattr
    call, which allowed local users to gain group privileges
    by leveraging the existence of a setgid program with
    restrictions on execute permissions (bnc#995968).

  - CVE-2015-8956: The rfcomm_sock_bind function in
    net/bluetooth/rfcomm/sock.c in the Linux kernel allowed
    local users to obtain sensitive information or cause a
    denial of service (NULL pointer dereference) via vectors
    involving a bind system call on a Bluetooth RFCOMM
    socket (bnc#1003925).

  - CVE-2016-8658: Stack-based buffer overflow in the
    brcmf_cfg80211_start_ap function in
    drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg8021
    1.c in the Linux kernel allowed local users to cause a
    denial of service (system crash) or possibly have
    unspecified other impact via a long SSID Information
    Element in a command to a Netlink socket (bnc#1004462).

  - CVE-2016-7425: The arcmsr_iop_message_xfer function in
    drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel did
    not restrict a certain length field, which allowed local
    users to gain privileges or cause a denial of service
    (heap-based buffer overflow) via an
    ARCMSR_MESSAGE_WRITE_WQBUFFER control code (bnc#999932).

  - CVE-2016-6327: drivers/infiniband/ulp/srpt/ib_srpt.c in
    the Linux kernel allowed local users to cause a denial
    of service (NULL pointer dereference and system crash)
    by using an ABORT_TASK command to abort a device write
    operation (bnc#994748).

  - CVE-2016-6828: The tcp_check_send_head function in
    include/net/tcp.h in the Linux kernel did not properly
    maintain certain SACK state after a failed data copy,
    which allowed local users to cause a denial of service
    (tcp_xmit_retransmit_queue use-after-free and system
    crash) via a crafted SACK option (bnc#994296).

  - CVE-2016-5696: net/ipv4/tcp_input.c in the Linux kernel
    did not properly determine the rate of challenge ACK
    segments, which made it easier for remote attackers to
    hijack TCP sessions via a blind in-window attack
    (bnc#989152).

  - CVE-2016-6130: Race condition in the sclp_ctl_ioctl_sccb
    function in drivers/s390/char/sclp_ctl.c in the Linux
    kernel allowed local users to obtain sensitive
    information from kernel memory by changing a certain
    length value, aka a 'double fetch' vulnerability
    (bnc#987542).

  - CVE-2016-6480: Race condition in the ioctl_send_fib
    function in drivers/scsi/aacraid/commctrl.c in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds access or system crash) by changing a
    certain size value, aka a 'double fetch' vulnerability
    (bnc#991608).

The following non-security bugs were fixed :

  - aacraid: Fix RRQ overload (bsc#1003079).

  - acpi / pm: Ignore wakeup setting if the ACPI companion
    can't wake up (FATE#315621).

  - af_vsock: Shrink the area influenced by prepare_to_wait
    (bsc#994520).

  - apparmor: add missing id bounds check on dfa
    verification (bsc#1000304).

  - apparmor: check that xindex is in trans_table bounds
    (bsc#1000304).

  - apparmor: do not check for vmalloc_addr if kvzalloc()
    failed (bsc#1000304).

  - apparmor: do not expose kernel stack (bsc#1000304).

  - apparmor: ensure the target profile name is always
    audited (bsc#1000304).

  - apparmor: exec should not be returning ENOENT when it
    denies (bsc#1000304).

  - apparmor: fix arg_size computation for when setprocattr
    is null terminated (bsc#1000304).

  - apparmor: fix audit full profile hname on successful
    load (bsc#1000304).

  - apparmor: fix change_hat not finding hat after policy
    replacement (bsc#1000287).

  - apparmor: fix disconnected bind mnts reconnection
    (bsc#1000304).

  - apparmor: fix log failures for all profiles in a set
    (bsc#1000304).

  - apparmor: fix module parameters can be changed after
    policy is locked (bsc#1000304).

  - apparmor: fix oops in profile_unpack() when policy_db is
    not present (bsc#1000304).

  - apparmor: fix oops, validate buffer size in
    apparmor_setprocattr() (bsc#1000304).

  - apparmor: fix put() parent ref after updating the active
    ref (bsc#1000304).

  - apparmor: fix refcount bug in profile replacement
    (bsc#1000304).

  - apparmor: fix refcount race when finding a child profile
    (bsc#1000304).

  - apparmor: fix replacement bug that adds new child to old
    parent (bsc#1000304).

  - apparmor: fix uninitialized lsm_audit member
    (bsc#1000304).

  - apparmor: fix update the mtime of the profile file on
    replacement (bsc#1000304).

  - apparmor: internal paths should be treated as
    disconnected (bsc#1000304).

  - apparmor: use list_next_entry instead of list_entry_next
    (bsc#1000304).

  - arm64: Ensure pmd_present() returns false after
    pmd_mknotpresent() (Automatic NUMA Balancing
    (fate#315482)).

  - arm64: mm: remove broken &= operator from
    pmd_mknotpresent (Automatic NUMA Balancing
    (fate#315482)).

  - avoid dentry crash triggered by NFS (bsc#984194).

  - be2net: Do not leak iomapped memory on removal
    (bsc#921784 FATE#318561).

  - be2net: fix BE3-R FW download compatibility check
    (bsc#921784 FATE#318561).

  - be2net: fix wrong return value in
    be_check_ufi_compatibility() (bsc#921784 FATE#318561).

  - be2net: remove vlan promisc capability from VF's profile
    descriptors (bsc#921784 FATE#318561).

  - blacklist.conf :

  - blacklist.conf: 78f3d050c34b We do not support fsl
    hardware

  - blacklist.conf: add 5195c14c8b27 (reverted and
    superseded by a commit we already have)

  - blacklist.conf: Add entry for
    7bf52fb891b64b8d61caf0b82060adb9db761aec The commit
    7bf52fb891b6 ('mm: vmscan: reclaim highmem zone if
    buffer_heads is over limit') is unnecessary as the fix
    is also available from commit d4debc66d1fc ('vmscan:
    remove unnecessary temporary vars in
    do_try_to_free_pages').

  - blacklist.conf: add pointless networking follow-up fixes

  - blacklist.conf: Add two fanotify commits which we do not
    need (fixes tag was not quite accurate)

  - blacklist.conf: Blacklist unsupported architectures

  - blkfront: fix an error path memory leak (luckily none so
    far).

  - blk-mq: fix undefined behaviour in order_to_size()
    (fate#315209).

  - blktap2: eliminate deadlock potential from shutdown path
    (bsc#909994).

  - blktap2: eliminate race from deferred work queue
    handling (bsc#911687).

  - bond: Check length of IFLA_BOND_ARP_IP_TARGET attributes
    (fate#316924).

  - bonding: always set recv_probe to bond_arp_rcv in arp
    monitor (bsc#977687).

  - bonding: fix curr_active_slave/carrier with loadbalance
    arp monitoring (fate#316924).

  - bonding: Prevent IPv6 link local address on enslaved
    devices (fate#316924).

  - bonding: prevent out of bound accesses (fate#316924).

  - bonding: set carrier off for devices created through
    netlink (bsc#999577).

  - btrfs: account for non-CoW'd blocks in
    btrfs_abort_transaction (bsc#983619).

  - btrfs: add missing discards when unpinning extents with
    -o discard (bsc#904489).

  - btrfs: btrfs_issue_discard ensure offset/length are
    aligned to sector boundaries (bsc#904489).

  - btrfs: do not create or leak aliased root while cleaning
    up orphans (bsc#904489).

  - btrfs: ensure that file descriptor used with subvol
    ioctls is a dir (bsc#999600).

  - btrfs: explictly delete unused block groups in
    close_ctree and ro-remount (bsc#904489).

  - btrfs: Fix a data space underflow warning (bsc#985562,
    bsc#975596, bsc#984779)

  - btrfs: fix fitrim discarding device area reserved for
    boot loader's use (bsc#904489).

  - btrfs: handle quota reserve failure properly
    (bsc#1005666).

  - btrfs: iterate over unused chunk space in FITRIM
    (bsc#904489).

  - btrfs: make btrfs_issue_discard return bytes discarded
    (bsc#904489).

  - btrfs: properly track when rescan worker is running
    (bsc#989953).

  - btrfs: remove unnecessary locking of cleaner_mutex to
    avoid deadlock (bsc#904489).

  - btrfs: reorder patches to place local patches back at
    the end of the series

  - btrfs: skip superblocks during discard (bsc#904489).

  - btrfs: test_check_exists: Fix infinite loop when
    searching for free space entries (bsc#987192).

  - btrfs: waiting on qgroup rescan should not always be
    interruptible (bsc#992712).

  - cdc-acm: added sanity checking for probe() (bsc#993891).

  - cephfs: ignore error from
    invalidate_inode_pages2_range() in direct write
    (bsc#995153).

  - cephfs: remove warning when ceph_releasepage() is called
    on dirty page (bsc#995153).

  - clockevents: export clockevents_unbind_device instead of
    clockevents_unbind (bnc#937888).

  - conntrack: RFC5961 challenge ACK confuse conntrack
    LAST-ACK transition (bsc#966864).

  - cpumask, nodemask: implement cpumask/nodemask_pr_args()
    (bnc1003866).

  - cxgbi: fix uninitialized flowi6 (bsc#924384 FATE#318570
    bsc#921338).

  - dm: fix AB-BA deadlock in __dm_destroy(). (bsc#970943)

  - drivers/hv: share Hyper-V SynIC constants with userspace
    (bnc#937888).

  - drivers: hv: vmbus: avoid scheduling in interrupt
    context in vmbus_initiate_unload() (bnc#937888).

  - drivers: hv: vmbus: avoid unneeded compiler
    optimizations in vmbus_wait_for_unload() (bnc#937888).

  - drivers: hv: vmbus: avoid wait_for_completion() on crash
    (bnc#937888).

  - drivers: hv: vmbus: Cleanup vmbus_set_event()
    (bnc#937888).

  - drivers: hv: vmbus: do not loose HVMSG_TIMER_EXPIRED
    messages (bnc#937888).

  - drivers: hv: vmbus: do not manipulate with clocksources
    on crash (bnc#937888).

  - drivers: hv: vmbus: Force all channel messages to be
    delivered on CPU 0 (bnc#937888).

  - drivers: hv: vmbus: Get rid of the unused irq variable
    (bnc#937888).

  - drivers: hv: vmbus: handle various crash scenarios
    (bnc#937888).

  - drivers: hv: vmbus: remove code duplication in message
    handling (bnc#937888).

  - drivers: hv: vmbus: Support handling messages on
    multiple CPUs (bnc#937888).

  - drivers: hv: vmbus: Support kexec on ws2012 r2 and above
    (bnc#937888).

  - efi: Small leak on error in runtime map code
    (fate#315019).

  - ext2: Enable ext2 driver in config files (bsc#976195,
    fate#320805)

  - ext4: Add parameter for tuning handling of ext2
    (bsc#976195).

  - Fix kabi change cause by adding flock_owner to
    open_context (bsc#998689).

  - fix pCPU handling (luckily none so far).

  - fix
    xfs-handle-dquot-buffer-readahead-in-log-recovery-co.pat
    ch (bsc#1003153).

  - fs/cifs: cifs_get_root shouldn't use path with tree name
    (bsc#963655, bsc#979681).

  - fs/cifs: Compare prepaths when comparing superblocks
    (bsc#799133).

  - fs/cifs: Fix memory leaks in cifs_do_mount()
    (bsc#799133).

  - fs/cifs: Fix regression which breaks DFS mounting
    (bsc#799133).

  - fs/cifs: make share unaccessible at root level mountable
    (bsc#799133).

  - fs/cifs: Move check for prefix path to within
    cifs_get_root() (bsc#799133).

  - fs/cifs: REVERT fix wrongly prefixed path to root
    (bsc#963655, bsc#979681)

  - fs/select: add vmalloc fallback for select(2)
    (bsc#1000189).

  - ftrace/x86: Set ftrace_stub to weak to prevent gcc from
    using short jumps to it (bsc#984419).

  - hyperv: enable call to clockevents_unbind_device in
    kexec/kdump path

  - hyperv: replace KEXEC_CORE by plain KEXEC because we
    lack 2965faa5e0 in the base kernel

  - i40e: fix an uninitialized variable bug (bnc#857397
    FATE#315659).

  - ib/IWPM: Fix a potential skb leak (bsc#924381
    FATE#318568 bsc#921338).

  - ib/mlx5: Fix RC transport send queue overhead
    computation (bnc#865545 FATE#316891).

  - introduce NETIF_F_GSO_ENCAP_ALL helper mask
    (bsc#1001486).

  - iommu/amd: Update Alias-DTE in update_device_table()
    (bsc#975772).

  - ipv6: fix multipath route replace error recovery
    (bsc#930399).

  - ipv6: KABI workaround for ipv6: add complete rcu
    protection around np->opt.

  - ipv6: send NEWLINK on RA managed/otherconf changes
    (bsc#934067).

  - ipv6: send only one NEWLINK when RA causes changes
    (bsc#934067).

  - iscsi: Add a missed complete in iscsit_close_connection
    (bsc#992555, bsc#987805).

  - iwlwifi: dvm: fix flush support for old firmware
    (bsc#940545).

  - kabi: clockevents: export clockevents_unbind again.

  - kabi: hide harmless change in struct
    inet_connection_sock (fate#318553).

  - kABI: protect backing-dev include in mm/migrate.

  - kABI: protect enum usb_device_speed.

  - kABI: protect struct mlx5_modify_qp_mbox_in.

  - kABI: protect struct mmc_packed (kabi).

  - kabi: work around kabi changes from commit 53f9ff48f636
    (bsc#988617).

  - kaweth: fix firmware download (bsc#993890).

  - kaweth: fix oops upon failed memory allocation
    (bsc#993890).

  - kernel/fork: fix CLONE_CHILD_CLEARTID regression in nscd
    (bnc#941420).

  - kernel/printk/printk.c: fix faulty logic in the case of
    recursive printk (bnc#744692, bnc#789311).

  - kvm: do not handle APIC access page if in-kernel irqchip
    is not in use (bsc#959463).

  - kvm: vmx: defer load of APIC access page address during
    reset (bsc#959463).

  - libceph: enable large, variable-sized OSD requests
    (bsc#988715).

  - libceph: make r_request msg_size calculation clearer
    (bsc#988715).

  - libceph: move r_reply_op_{len,result} into struct
    ceph_osd_req_op (bsc#988715).

  - libceph: osdc->req_mempool should be backed by a slab
    pool (bsc#988715).

  - libceph: rename ceph_osd_req_op::payload_len to
    indata_len (bsc#988715).

  - libfc: do not send ABTS when resetting exchanges
    (bsc#962846).

  - libfc: Do not take rdata->rp_mutex when processing a
    -FC_EX_CLOSED ELS response (bsc#962846).

  - libfc: Fixup disc_mutex handling (bsc#962846).

  - libfc: fixup locking of ptp_setup() (bsc#962846).

  - libfc: Issue PRLI after a PRLO has been received
    (bsc#962846).

  - libfc: reset exchange manager during LOGO handling
    (bsc#962846).

  - libfc: Revisit kref handling (bnc#990245).

  - libfc: sanity check cpu number extracted from xid
    (bsc#988440).

  - libfc: send LOGO for PLOGI failure (bsc#962846).

  - lib/vsprintf: implement bitmap printing through
    '%*pb[l]' (bnc#1003866).

  - md: check command validity early in md_ioctl()
    (bsc#1004520).

  - md: Drop sending a change uevent when stopping
    (bsc#1003568).

  - md: lockless I/O submission for RAID1 (bsc#982783).

  - md/raid5: fix a recently broken BUG_ON() (bsc#1006691).

  - memcg: convert threshold to bytes (bnc#931454).

  - memcg: fix thresholds for 32b architectures
    (bnc#931454).

  - mm, cma: prevent nr_isolated_* counters from going
    negative (bnc#971975 VM performance -- git fixes).

  - mm: thp: fix SMP race condition between THP page fault
    and MADV_DONTNEED (VM Functionality, bnc#986445).

  - module: Issue warnings when tainting kernel
    (bsc#974406).

  - mpt2sas, mpt3sas: Fix panic when aer correct error
    occurred (bsc#997708).

  - mpt3sas: Update
    patches.drivers/mpt3sas-Fix-use-sas_is_tlr_enabled-API-b
    efore-enabli.patch (bsc#967640, bsc#992244).

  - msi-x: fix an error path (luckily none so far).

  - netback: fix flipping mode (bsc#996664).

  - netback: fix refounting (bsc#978094).

  - netfront: do not truncate grant references.

  - netfront: use correct linear area after linearizing an
    skb (bsc#1007886).

  - nfs4: reset states to use open_stateid when returning
    delegation voluntarily (bsc#1003400).

  - nfs: Add a stub for GETDEVICELIST (bnc#898675).

  - nfs: Do not write enable new pages while an invalidation
    is proceeding (bsc#999584).

  - nfsd: Use free_conn to free connection (bsc#979451).

  - nfs: Fix an LOCK/OPEN race when unlinking an open file
    (bsc#956514).

  - nfs: Fix a regression in the read() syscall
    (bsc#999584).

  - nfs: fix BUG() crash in notify_change() with patch to
    chown_common() (bnc#876463).

  - nfs: fix pg_test page count calculation (bnc#898675).

  - nfs: nfs4_fl_prepare_ds must be careful about reporting
    success (bsc#1000776).

  - nfsv4: add flock_owner to open context (bnc#998689).

  - nfsv4: change nfs4_do_setattr to take an open_context
    instead of a nfs4_state (bnc#998689).

  - nfsv4: change nfs4_select_rw_stateid to take a
    lock_context inplace of lock_owner (bnc#998689).

  - nfsv4: enhance nfs4_copy_lock_stateid to use a flock
    stateid if there is one (bnc#998689).

  - nfsv4: Ensure nfs_atomic_open set the dentry verifier on
    ENOENT (bnc#866130).

  - oom: print nodemask in the oom report (bnc#1003866).

  - packet: tpacket_snd(): fix signed/unsigned comparison
    (bsc#874131).

  - perf/x86/intel: Fix bug for 'cycles:p' and 'cycles:pp'
    on SLM (bsc#997896).

  - pm / hibernate: Fix 2G size issue of snapshot image
    verification (bsc#1004252).

  - pm / hibernate: Fix rtree_next_node() to avoid walking
    off list ends (bnc#860441).

  - powerpc: add kernel parameter iommu_alloc_quiet
    (bsc#998825).

  - printk: add kernel parameter to control writes to
    /dev/kmsg (bsc#979928).

  - qgroup: Prevent qgroup->reserved from going subzero
    (bsc#993841).

  - qlcnic: potential NULL dereference in
    qlcnic_83xx_get_minidump_template() (bsc#922064
    FATE#318609)

  - radeon: avoid boot hang in Xen Dom0 (luckily none so
    far).

  - ratelimit: extend to print suppressed messages on
    release (bsc#979928).

  - ratelimit: fix bug in time interval by resetting right
    begin time (bsc#979928).

  - rbd: truncate objects on cmpext short reads
    (bsc#988715).

  - rcu: Fix improper use or RCU in
    patches.kabi/ipv6-add-complete-rcu-protection-around-np-
    opt.kabi.patch. (bsc#961257)

  - Refresh
    patches.suse/CFS-0259-ceph-Asynchronous-IO-support.patch
    . After a write, we must free the 'request', not the
    'response'. This error crept in during the backport.
    bsc#995153

  - Refresh patches.xen/xen3-patch-3.9 (bsc#991247).

  - Rename
    patches.xen/xen3-kgr-{0107,1003}-reserve-a-place-in-thre
    ad_struct-for-storing-RIP.patch to match its non-Xen
    counterpart.

  - Revert 'can: dev: fix deadlock reported after bus-off'.

  - Revert 'Input: i8042 - break load dependency between
    atkbd/psmouse and i8042'.

  - Revert 'Input: i8042 - set up shared ps2_cmd_mutex for
    AUX ports'.

  - rpm/config.sh: do not prepend '60.' to release string
    This is needed for SLE maintenance workflow, no need for
    that in evergreen-13.1.

  - rpm/config.sh: Set the SP1 release string to
    60.<RELEASE> (bsc#997059)

  - rpm/mkspec: Read a default release string from
    rpm/config.sh (bsc997059)

  - rtnetlink: avoid 0 sized arrays (fate#316924).

  - s390: add SMT support (bnc#994438, LTC#144756).

  - sched/core: Fix an SMP ordering race in try_to_wake_up()
    vs. schedule() (bnc#1001419).

  - sched/core: Fix a race between try_to_wake_up() and a
    woken up task (bsc#1002165, bsc#1001419).

  - scsi: ibmvfc: add FC Class 3 Error Recovery support
    (bsc#984992).

  - scsi: ibmvfc: Fix I/O hang when port is not mapped
    (bsc#971989)

  - scsi: ibmvfc: Set READ FCP_XFER_READY DISABLED bit in
    PRLI (bsc#984992).

  - sd: Fix memory leak caused by RESET_WP patch
    (bsc#999779).

  - squashfs3: properly handle dir_emit() failures
    (bsc#998795).

  - sunrpc: Add missing support for
    RPC_CLNT_CREATE_NO_RETRANS_TIMEOUT (bnc#868923).

  - sunrpc: Fix a regression when reconnecting (bsc#946309).

  - supported.conf: Add ext2

  - supported.conf: Add iscsi modules to -base (bsc#997299)

  - supported.conf: Add tun to -base (bsc#992593)

  - supported.conf: Add veth to -base (bsc#992591)

  - target: Fix missing complete during ABORT_TASK +
    CMD_T_FABRIC_STOP (bsc#987621).

  - target: Fix race between iscsi-target connection
    shutdown + ABORT_TASK (bsc#987621).

  - tcp: add proper TS val into RST packets (bsc#937086).

  - tcp: align tcp_xmit_size_goal() on tcp_tso_autosize()
    (bsc#937086).

  - tcp: fix child sockets to use system default congestion
    control if not set (fate#318553).

  - tcp: fix cwnd limited checking to improve congestion
    control (bsc#988617).

  - tcp: refresh skb timestamp at retransmit time
    (bsc#937086).

  - timers: Use proper base migration in add_timer_on()
    (bnc#993392).

  - tunnels: Do not apply GRO to multiple layers of
    encapsulation (bsc#1001486).

  - tunnels: Remove encapsulation offloads on decap
    (bsc#1001486).

  - Update patches.kabi/kabi.clockevents_unbind.patch
    (bnc#937888).

  - uprobes: Fix the memcg accounting (bnc#931454).

  - usb: fix typo in wMaxPacketSize validation (bsc#991665).

  - usbhid: add ATEN CS962 to list of quirky devices
    (bsc#1007615).

  - usb: hub: Fix auto-remount of safely removed or ejected
    USB-3 devices (bsc#922634).

  - usb: validate wMaxPacketValue entries in endpoint
    descriptors (bnc#991665).

  - vmxnet3: Wake queue from reset work (bsc#999907).

  - x86/tlb/trace: Do not trace on CPU that is offline (TLB
    Performance git-fixes).

  - xenbus: do not invoke ->is_ready() for most device
    states (bsc#987333).

  - xenbus: inspect the correct type in
    xenbus_dev_request_and_reply().

  - xen: Linux 3.12.63.

  - xen: Linux 3.12.64.

  - xen/pciback: Fix conf_space read/write overlap check.

  - xen-pciback: return proper values during BAR sizing.

  - xen: x86/mm/pat, /dev/mem: Remove superfluous error
    message (bsc#974620).

  - xfs: fixed signedness of error code in
    xfs_inode_buf_verify (bsc#1003153).

  - xfs: handle dquot buffer readahead in log recovery
    correctly (bsc#955446).

  - xfs: Silence warnings in xfs_vm_releasepage()
    (bnc#915183 bsc#987565).

  - xhci: silence warnings in switch (bnc#991665)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=744692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=772786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=789311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=799133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=857397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=860441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=865545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=866130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=868923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=874131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=875631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=876145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=876463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=898675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=904489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=909994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=911687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=915183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=921338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=921784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=924381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=924384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=930399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=934067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=940545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=941420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=946309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=992244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=992555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=992591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=992593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=992712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=995153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=995968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=996664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=997059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=997299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=997708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=997896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=998689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=998795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=998825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999932"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/07");
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

if ( rpm_check(release:"SUSE13.1", reference:"cloop-2.639-11.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-debuginfo-2.639-11.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-debugsource-2.639-11.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-default-2.639_k3.12.67_58-11.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-default-debuginfo-2.639_k3.12.67_58-11.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-desktop-2.639_k3.12.67_58-11.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-desktop-debuginfo-2.639_k3.12.67_58-11.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-pae-2.639_k3.12.67_58-11.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-pae-debuginfo-2.639_k3.12.67_58-11.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-xen-2.639_k3.12.67_58-11.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-xen-debuginfo-2.639_k3.12.67_58-11.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-7.0.2-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-debuginfo-7.0.2-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-debugsource-7.0.2-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-devel-7.0.2-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-eppic-7.0.2-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-eppic-debuginfo-7.0.2-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-gcore-7.0.2-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-gcore-debuginfo-7.0.2-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-default-7.0.2_k3.12.67_58-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-default-debuginfo-7.0.2_k3.12.67_58-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-desktop-7.0.2_k3.12.67_58-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-desktop-debuginfo-7.0.2_k3.12.67_58-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-pae-7.0.2_k3.12.67_58-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-pae-debuginfo-7.0.2_k3.12.67_58-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-xen-7.0.2_k3.12.67_58-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-xen-debuginfo-7.0.2_k3.12.67_58-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-debugsource-1.28-16.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-default-1.28_k3.12.67_58-16.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-default-debuginfo-1.28_k3.12.67_58-16.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-desktop-1.28_k3.12.67_58-16.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-desktop-debuginfo-1.28_k3.12.67_58-16.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-pae-1.28_k3.12.67_58-16.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-pae-debuginfo-1.28_k3.12.67_58-16.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-xen-1.28_k3.12.67_58-16.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-xen-debuginfo-1.28_k3.12.67_58-16.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-6.21.1-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-debuginfo-6.21.1-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-debugsource-6.21.1-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-devel-6.21.1-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-default-6.21.1_k3.12.67_58-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-default-debuginfo-6.21.1_k3.12.67_58-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-desktop-6.21.1_k3.12.67_58-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-desktop-debuginfo-6.21.1_k3.12.67_58-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-pae-6.21.1_k3.12.67_58-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-pae-debuginfo-6.21.1_k3.12.67_58-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-xen-6.21.1_k3.12.67_58-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-xen-debuginfo-6.21.1_k3.12.67_58-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-1.4.20.3-13.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-debuginfo-1.4.20.3-13.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-debugsource-1.4.20.3-13.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-default-1.4.20.3_k3.12.67_58-13.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-default-debuginfo-1.4.20.3_k3.12.67_58-13.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-desktop-1.4.20.3_k3.12.67_58-13.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-desktop-debuginfo-1.4.20.3_k3.12.67_58-13.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-pae-1.4.20.3_k3.12.67_58-13.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-pae-debuginfo-1.4.20.3_k3.12.67_58-13.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-xen-1.4.20.3_k3.12.67_58-13.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-xen-debuginfo-1.4.20.3_k3.12.67_58-13.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-base-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-base-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-debugsource-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-devel-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-devel-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-macros-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-source-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-source-vanilla-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-syms-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libipset3-6.21.1-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libipset3-debuginfo-6.21.1-2.40.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-1.58-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-debuginfo-1.58-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-debugsource-1.58-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-default-1.58_k3.12.67_58-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-default-debuginfo-1.58_k3.12.67_58-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-desktop-1.58_k3.12.67_58-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-desktop-debuginfo-1.58_k3.12.67_58-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-pae-1.58_k3.12.67_58-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-pae-debuginfo-1.58_k3.12.67_58-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-1.11.0-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-controller-1.11.0-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-controller-debuginfo-1.11.0-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-debuginfo-1.11.0-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-debugsource-1.11.0-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-default-1.11.0_k3.12.67_58-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-default-debuginfo-1.11.0_k3.12.67_58-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-desktop-1.11.0_k3.12.67_58-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-desktop-debuginfo-1.11.0_k3.12.67_58-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-pae-1.11.0_k3.12.67_58-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-pae-debuginfo-1.11.0_k3.12.67_58-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-xen-1.11.0_k3.12.67_58-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-xen-debuginfo-1.11.0_k3.12.67_58-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-pki-1.11.0-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-switch-1.11.0-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-switch-debuginfo-1.11.0-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-test-1.11.0-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-0.44-258.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-debuginfo-0.44-258.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-debugsource-0.44-258.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-default-0.44_k3.12.67_58-258.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-default-debuginfo-0.44_k3.12.67_58-258.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-desktop-0.44_k3.12.67_58-258.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-desktop-debuginfo-0.44_k3.12.67_58-258.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-pae-0.44_k3.12.67_58-258.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-pae-debuginfo-0.44_k3.12.67_58-258.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-openvswitch-1.11.0-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-openvswitch-test-1.11.0-0.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-virtualbox-4.2.36-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-virtualbox-debuginfo-4.2.36-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-debugsource-20130607-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-default-20130607_k3.12.67_58-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-default-debuginfo-20130607_k3.12.67_58-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-desktop-20130607_k3.12.67_58-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-desktop-debuginfo-20130607_k3.12.67_58-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-pae-20130607_k3.12.67_58-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-pae-debuginfo-20130607_k3.12.67_58-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-xen-20130607_k3.12.67_58-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-xen-debuginfo-20130607_k3.12.67_58-2.36.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-4.2.36-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-debuginfo-4.2.36-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-debugsource-4.2.36-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-devel-4.2.36-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-default-4.2.36_k3.12.67_58-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-default-debuginfo-4.2.36_k3.12.67_58-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-desktop-4.2.36_k3.12.67_58-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-desktop-debuginfo-4.2.36_k3.12.67_58-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-pae-4.2.36_k3.12.67_58-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-pae-debuginfo-4.2.36_k3.12.67_58-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-tools-4.2.36-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-tools-debuginfo-4.2.36-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-x11-4.2.36-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-x11-debuginfo-4.2.36-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-default-4.2.36_k3.12.67_58-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-default-debuginfo-4.2.36_k3.12.67_58-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-desktop-4.2.36_k3.12.67_58-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-desktop-debuginfo-4.2.36_k3.12.67_58-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-pae-4.2.36_k3.12.67_58-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-pae-debuginfo-4.2.36_k3.12.67_58-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-source-4.2.36-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-qt-4.2.36-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-qt-debuginfo-4.2.36-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-websrv-4.2.36-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-websrv-debuginfo-4.2.36-2.68.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-debugsource-4.3.4_10-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-devel-4.3.4_10-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-default-4.3.4_10_k3.12.67_58-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-default-debuginfo-4.3.4_10_k3.12.67_58-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-desktop-4.3.4_10_k3.12.67_58-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-desktop-debuginfo-4.3.4_10_k3.12.67_58-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-pae-4.3.4_10_k3.12.67_58-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-pae-debuginfo-4.3.4_10_k3.12.67_58-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-libs-4.3.4_10-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-libs-debuginfo-4.3.4_10-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-tools-domU-4.3.4_10-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-tools-domU-debuginfo-4.3.4_10-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-2.3-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-debuginfo-2.3-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-debugsource-2.3-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-default-2.3_k3.12.67_58-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-default-debuginfo-2.3_k3.12.67_58-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-desktop-2.3_k3.12.67_58-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-desktop-debuginfo-2.3_k3.12.67_58-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-pae-2.3_k3.12.67_58-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-pae-debuginfo-2.3_k3.12.67_58-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-xen-2.3_k3.12.67_58-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-xen-debuginfo-2.3_k3.12.67_58-2.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-base-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-debugsource-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-devel-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-base-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-debugsource-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-devel-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-base-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-debugsource-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-devel-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-base-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-debugsource-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-devel-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-base-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-base-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-debugsource-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-devel-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-debugsource-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-devel-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-base-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-debugsource-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-devel-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-base-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-debugsource-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-devel-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-base-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-devel-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-base-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-devel-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-base-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-debugsource-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-devel-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-base-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-base-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-debugsource-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-devel-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-devel-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-base-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.67-58.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-4.3.4_10-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-doc-html-4.3.4_10-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-libs-32bit-4.3.4_10-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.3.4_10-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-tools-4.3.4_10-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-tools-debuginfo-4.3.4_10-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-xend-tools-4.3.4_10-69.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-xend-tools-debuginfo-4.3.4_10-69.1") ) flag++;

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
