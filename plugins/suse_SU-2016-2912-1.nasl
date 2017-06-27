#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2912-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(95368);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2016/12/27 20:33:26 $");

  script_cve_id("CVE-2015-8956", "CVE-2016-5696", "CVE-2016-6130", "CVE-2016-6327", "CVE-2016-6480", "CVE-2016-6828", "CVE-2016-7039", "CVE-2016-7042", "CVE-2016-7097", "CVE-2016-7425", "CVE-2016-8658", "CVE-2016-8666");
  script_osvdb_id(140796, 141441, 142610, 142992, 143247, 143514, 144411, 145102, 145388, 145585, 145586, 145649, 145694);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2016:2912-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 kernel was updated to 3.12.67 to receive
various security and bugfixes. The following security bugs were 
fixed :

  - CVE-2016-7042: The proc_keys_show function in
    security/keys/proc.c in the Linux kernel used an
    incorrect buffer size for certain timeout data, which
    allowed local users to cause a denial of service (stack
    memory corruption and panic) by reading the /proc/keys
    file (bsc#1004517).

  - CVE-2016-7097: The filesystem implementation in the
    Linux kernel preserved the setgid bit during a setxattr
    call, which allowed local users to gain group privileges
    by leveraging the existence of a setgid program with
    restrictions on execute permissions (bsc#995968).

  - CVE-2015-8956: The rfcomm_sock_bind function in
    net/bluetooth/rfcomm/sock.c in the Linux kernel allowed
    local users to obtain sensitive information or cause a
    denial of service (NULL pointer dereference) via vectors
    involving a bind system call on a Bluetooth RFCOMM
    socket (bnc#1003925).

  - CVE-2016-5696: net/ipv4/tcp_input.c in the Linux kernel
    did not properly determine the rate of challenge ACK
    segments, which made it easier for man-in-the-middle
    attackers to hijack TCP sessions via a blind in-window
    attack (bnc#989152).

  - CVE-2016-6130: Race condition in the sclp_ctl_ioctl_sccb
    function in drivers/s390/char/sclp_ctl.c in the Linux
    kernel allowed local users to obtain sensitive
    information from kernel memory by changing a certain
    length value, aka a 'double fetch' vulnerability
    (bnc#987542).

  - CVE-2016-6327: drivers/infiniband/ulp/srpt/ib_srpt.c in
    the Linux kernel allowed local users to cause a denial
    of service (NULL pointer dereference and system crash)
    by using an ABORT_TASK command to abort a device write
    operation (bnc#994748).

  - CVE-2016-6480: Race condition in the ioctl_send_fib
    function in drivers/scsi/aacraid/commctrl.c in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds access or system crash) by changing a
    certain size value, aka a 'double fetch' vulnerability
    (bnc#991608).

  - CVE-2016-6828: The tcp_check_send_head function in
    include/net/tcp.h in the Linux kernel did not properly
    maintain certain SACK state after a failed data copy,
    which allowed local users to cause a denial of service
    (tcp_xmit_retransmit_queue use-after-free and system
    crash) via a crafted SACK option (bnc#994296).

  - CVE-2016-7425: The arcmsr_iop_message_xfer function in
    drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel did
    not restrict a certain length field, which allowed local
    users to gain privileges or cause a denial of service
    (heap-based buffer overflow) via an
    ARCMSR_MESSAGE_WRITE_WQBUFFER control code (bnc#999932).

  - CVE-2016-8658: Stack-based buffer overflow in the
    brcmf_cfg80211_start_ap function in
    drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg8021
    1.c in the Linux kernel allowed local users to cause a
    denial of service (system crash) or possibly have
    unspecified other impact via a long SSID Information
    Element in a command to a Netlink socket (bnc#1004462).

  - CVE-2016-8666: The IP stack in the Linux kernel allowed
    remote attackers to cause a denial of service (stack
    consumption and panic) or possibly have unspecified
    other impact by triggering use of the GRO path for
    packets with tunnel stacking, as demonstrated by
    interleaved IPv4 headers and GRE headers, a related
    issue to CVE-2016-7039 (bsc#1001486). The following
    non-security bugs were fixed :

  - aacraid: Fix RRQ overload (bsc#1003079).

  - acpi / PM: Ignore wakeup setting if the ACPI companion
    can't wake up (FATE#315621).

  - AF_VSOCK: Shrink the area influenced by prepare_to_wait
    (bsc#994520).

  - apparmor: add missing id bounds check on dfa
    verification (bsc#1000304).

  - apparmor: check that xindex is in trans_table bounds
    (bsc#1000304).

  - apparmor: do not expose kernel stack (bsc#1000304).

  - apparmor: don't check for vmalloc_addr if kvzalloc()
    failed (bsc#1000304).

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

  - be2net: Don't leak iomapped memory on removal
    (bsc#921784).

  - be2net: fix BE3-R FW download compatibility check
    (bsc#921784).

  - be2net: fix wrong return value in
    be_check_ufi_compatibility() (bsc#921784).

  - be2net: remove vlan promisc capability from VF's profile
    descriptors (bsc#921784).

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

  - ceph: After a write, we must free the 'request', not the
    'response'. This error crept in during the backport.
    bsc#995153

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

  - Document the process to blacklist upstream commit-ids

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

  - ext4: Fixup handling for custom configs.

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

  - ib/iwpm: Fix a potential skb leak (bsc#924381
    FATE#318568 bsc#921338).

  - ib/mlx5: Fix RC transport send queue overhead
    computation (bnc#865545 FATE#316891).

  - input: Revert 'can: dev: fix deadlock reported after
    bus-off'.

  - input: Revert 'Input: i8042 - break load dependency
    between atkbd/psmouse and i8042'.

  - input: Revert 'Input: i8042 - set up shared
    ps2_cmd_mutex for AUX ports'.

  - introduce NETIF_F_GSO_ENCAP_ALL helper mask
    (bsc#1001486).

  - iommu/amd: Update Alias-DTE in update_device_table()
    (bsc#975772).

  - ipv6: Fix improper use or RCU (bsc#961257)

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

  - kabi: Fix kabi change cause by adding flock_owner to
    open_context (bsc#998689).

  - kabi: hide harmless change in struct
    inet_connection_sock (fate#318553).

  - kABI: protect backing-dev include in mm/migrate.

  - kABI: protect enum usb_device_speed.

  - kABI: protect struct mlx5_modify_qp_mbox_in.

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

  - Kvm: vmx: defer load of APIC access page address during
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

  - MSI-X: fix an error path (luckily none so far).

  - netback: fix flipping mode (bsc#996664).

  - netback: fix refounting (bsc#978094).

  - netfront: don't truncate grant references.

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

  - rpm/config.sh: Set the SP1 release string to
    60.<release> (bsc#997059)

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

  - Update
    patches.drivers/mpt3sas-Fix-use-sas_is_tlr_enabled-API-b
    efore-enabli.patch (bsc#967640, bsc#992244).

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

  - xenbus: don't invoke ->is_ready() for most device states
    (bsc#987333).

  - xenbus: inspect the correct type in
    xenbus_dev_request_and_reply().

  - xen: Linux 3.12.63.

  - xen/pciback: Fix conf_space read/write overlap check.

  - xen-pciback: return proper values during BAR sizing.

  - xen: Refresh patches.xen/xen3-patch-3.9 (bsc#991247).

  - xen: x86/mm/pat, /dev/mem: Remove superfluous error
    message (bsc#974620).

  - xfs: fixed signedness of error code in
    xfs_inode_buf_verify (bsc#1003153).

  - xfs: fix
    xfs-handle-dquot-buffer-readahead-in-log-recovery-co.pat
    ch (bsc#1003153).

  - xfs: handle dquot buffer readahead in log recovery
    correctly (bsc#955446).

  - xfs: Silence warnings in xfs_vm_releasepage()
    (bnc#915183 bsc#987565).

  - xhci: silence warnings in switch (bnc#991665).</release>

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1001419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1001486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1002165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1004252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1004462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1004517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1004520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1007615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1007886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/744692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/772786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/789311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/857397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/860441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/865545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/866130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/868923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/874131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/876463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/898675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/911687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/941420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/946309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/990245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/995153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/995968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/996664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/997059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/997299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/997708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/997896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8956.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5696.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6130.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6327.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6480.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6828.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7097.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7425.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8658.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8666.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162912-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96b59059"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1:zypper in -t patch
SUSE-SLE-WE-12-SP1-2016-1700=1

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1700=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1700=1

SUSE Linux Enterprise Module for Public Cloud 12:zypper in -t patch
SUSE-SLE-Module-Public-Cloud-12-2016-1700=1

SUSE Linux Enterprise Live Patching 12:zypper in -t patch
SUSE-SLE-Live-Patching-12-2016-1700=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1700=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");
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
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"kernel-default-man-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-debuginfo-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debuginfo-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debugsource-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-devel-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-syms-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-devel-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-syms-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.67-60.64.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.67-60.64.18.1")) flag++;


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
