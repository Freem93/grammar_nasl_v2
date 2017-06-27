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
  script_id(72163);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/02/10 11:36:54 $");

  script_cve_id("CVE-2013-4345", "CVE-2013-4483", "CVE-2013-4511", "CVE-2013-4514", "CVE-2013-4515", "CVE-2013-4587", "CVE-2013-4592", "CVE-2013-6367", "CVE-2013-6368", "CVE-2013-6378", "CVE-2013-6380", "CVE-2013-6383", "CVE-2013-7027", "CVE-2013-7266", "CVE-2013-7267", "CVE-2013-7268", "CVE-2013-7269", "CVE-2013-7270", "CVE-2013-7271");

  script_name(english:"SuSE 11.2 Security Update : Linux kernel (SAT Patch Numbers 8779 / 8791 / 8792)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 2 kernel was updated to
3.0.101 and also includes various other bug and security fixes.

A new feature was added :

  - supported.conf: marked net/netfilter/xt_set as supported
    (bnc#851066)(fate#313309) The following security bugs
    have been fixed :

  - Array index error in the kvm_vm_ioctl_create_vcpu
    function in virt/kvm/kvm_main.c in the KVM subsystem in
    the Linux kernel through 3.12.5 allows local users to
    gain privileges via a large id value. (bnc#853050).
    (CVE-2013-4587)

  - The KVM subsystem in the Linux kernel through 3.12.5
    allows local users to gain privileges or cause a denial
    of service (system crash) via a VAPIC synchronization
    operation involving a page-end address. (bnc#853052).
    (CVE-2013-6368)

  - The apic_get_tmcct function in arch/x86/kvm/lapic.c in
    the KVM subsystem in the Linux kernel through 3.12.5
    allows guest OS users to cause a denial of service
    (divide-by-zero error and host OS crash) via crafted
    modifications of the TMICT value. (bnc#853051).
    (CVE-2013-6367)

  - Memory leak in the __kvm_set_memory_region function in
    virt/kvm/kvm_main.c in the Linux kernel before 3.9
    allows local users to cause a denial of service (memory
    consumption) by leveraging certain device access to
    trigger movement of memory slots. (bnc#851101).
    (CVE-2013-4592)

  - The lbs_debugfs_write function in
    drivers/net/wireless/libertas/debugfs.c in the Linux
    kernel through 3.12.1 allows local users to cause a
    denial of service (OOPS) by leveraging root privileges
    for a zero-length write operation. (bnc#852559).
    (CVE-2013-6378)

  - Multiple buffer overflows in
    drivers/staging/wlags49_h2/wl_priv.c in the Linux kernel
    before 3.12 allow local users to cause a denial of
    service or possibly have unspecified other impact by
    leveraging the CAP_NET_ADMIN capability and providing a
    long station-name string, related to the (1)
    wvlan_uil_put_info and (2) wvlan_set_station_nickname
    functions. (bnc#849029). (CVE-2013-4514)

  - The bcm_char_ioctl function in
    drivers/staging/bcm/Bcmchar.c in the Linux kernel before
    3.12 does not initialize a certain data structure, which
    allows local users to obtain sensitive information from
    kernel memory via an IOCTL_BCM_GET_DEVICE_DRIVER_INFO
    ioctl call. (bnc#849034). (CVE-2013-4515)

  - The ieee80211_radiotap_iterator_init function in
    net/wireless/radiotap.c in the Linux kernel before
    3.11.7 does not check whether a frame contains any data
    outside of the header, which might allow attackers to
    cause a denial of service (buffer over-read) via a
    crafted header. (bnc#854634). (CVE-2013-7027)

  - The ipc_rcu_putref function in ipc/util.c in the Linux
    kernel before 3.10 does not properly manage a reference
    count, which allows local users to cause a denial of
    service (memory consumption or system crash) via a
    crafted application. (bnc#848321). (CVE-2013-4483)

  - Multiple integer overflows in Alchemy LCD frame-buffer
    drivers in the Linux kernel before 3.12 allow local
    users to create a read-write memory mapping for the
    entirety of kernel memory, and consequently gain
    privileges, via crafted mmap operations, related to the
    (1) au1100fb_fb_mmap function in
    drivers/video/au1100fb.c and the (2) au1200fb_fb_mmap
    function in drivers/video/au1200fb.c. (bnc#849021).
    (CVE-2013-4511)

  - The aac_send_raw_srb function in
    drivers/scsi/aacraid/commctrl.c in the Linux kernel
    through 3.12.1 does not properly validate a certain size
    value, which allows local users to cause a denial of
    service (invalid pointer dereference) or possibly have
    unspecified other impact via an FSACTL_SEND_RAW_SRB
    ioctl call that triggers a crafted SRB command.
    (bnc#852373). (CVE-2013-6380)

  - Linux kernel built with the networking
    support(CONFIG_NET) is vulnerable to an information
    leakage flaw in the socket layer. It could occur while
    doing recvmsg(2), recvfrom(2) socket calls. It occurs
    due to improperly initialised msg_name &amp; msg_namelen
    message header parameters. (bnc#854722). (CVE-2013-6463)

  - The aac_compat_ioctl function in
    drivers/scsi/aacraid/linit.c in the Linux kernel before
    3.11.8 does not require the CAP_SYS_RAWIO capability,
    which allows local users to bypass intended access
    restrictions via a crafted ioctl call. (bnc#852558).
    (CVE-2013-6383)

  - Off-by-one error in the get_prng_bytes function in
    crypto/ansi_cprng.c in the Linux kernel through 3.11.4
    makes it easier for context-dependent attackers to
    defeat cryptographic protection mechanisms via multiple
    requests for small amounts of data, leading to improper
    management of the state of the consumed data.
    (bnc#840226). (CVE-2013-4345)

Also the following non-security bugs have been fixed :

  - kabi: protect bind_conflict callback in struct
    inet_connection_sock_af_ops. (bnc#823618)

  - printk: forcibly flush nmi ringbuffer if oops is in
    progress. (bnc#849675)

  - blktrace: Send BLK_TN_PROCESS events to all running
    traces. (bnc#838623)

  - x86/dumpstack: Fix printk_address for direct addresses.
    (bnc#845621)

  - futex: fix handling of read-only-mapped hugepages (VM
    Functionality).

  - random: fix accounting race condition with lockless irq
    entropy_count update. (bnc#789359)

  - Provide realtime priority kthread and workqueue boot
    options. (bnc#836718)

  - sched: Fix several races in CFS_BANDWIDTH. (bnc#848336)

  - sched: Fix cfs_bandwidth misuse of
    hrtimer_expires_remaining. (bnc#848336)

  - sched: Fix hrtimer_cancel()/rq->lock deadlock.
    (bnc#848336)

  - sched: Fix race on toggling cfs_bandwidth_used.
    (bnc#848336)

  - sched: Fix buglet in return_cfs_rq_runtime().

  - sched: Guarantee new group-entities always have weight.
    (bnc#848336)

  - sched: Use jump labels to reduce overhead when bandwidth
    control is inactive. (bnc#848336)

  - watchdog: Get rid of MODULE_ALIAS_MISCDEV statements.
    (bnc#827767)

  - tcp: bind() fix autoselection to share ports.
    (bnc#823618)

  - tcp: bind() use stronger condition for bind_conflict.
    (bnc#823618)

  - tcp: ipv6: bind() use stronger condition for
    bind_conflict. (bnc#823618)

  - macvlan: disable LRO on lower device instead of macvlan.
    (bnc#846984)

  - macvlan: introduce IFF_MACVLAN flag and helper function.
    (bnc#846984)

  - macvlan: introduce macvlan_dev_real_dev() helper
    function. (bnc#846984)

  - xen: netback: bump tx queue length. (bnc#849404)

  - xen: xen_spin_kick fixed crash/lock release
    (bnc#807434)(bnc#848652).

  - xen: fixed USB passthrough issue. (bnc#852624)

  - netxen: fix off by one bug in
    netxen_release_tx_buffer(). (bnc#845729)

  - xfrm: invalidate dst on policy insertion/deletion.
    (bnc#842239)

  - xfrm: prevent ipcomp scratch buffer race condition.
    (bnc#842239)

  - crypto: Fix aes-xts parameter corruption (bnc#854546,
    LTC#100718).

  - crypto: gf128mul - fix call to memset() (obvious fix).

  - autofs4: autofs4_wait() vs. autofs4_catatonic_mode()
    race. (bnc#851314)

  - autofs4: catatonic_mode vs. notify_daemon race.
    (bnc#851314)

  - autofs4: close the races around autofs4_notify_daemon().
    (bnc#851314)

  - autofs4: deal with autofs4_write/autofs4_write races.
    (bnc#851314)

  - autofs4 - dont clear DCACHE_NEED_AUTOMOUNT on rootless
    mount. (bnc#851314)

  - autofs4 - fix deal with autofs4_write races.
    (bnc#851314)

  - autofs4 - use simple_empty() for empty directory check.
    (bnc#851314)

  - blkdev_max_block: make private to fs/buffer.c.
    (bnc#820338)

  - Avoid softlockup in shrink_dcache_for_umount_subtree.
    (bnc#834473)

  - dlm: set zero linger time on sctp socket. (bnc#787843)

  - SUNRPC: Fix a data corruption issue when retransmitting
    RPC calls. (bnc#855037)

  - nfs: Change NFSv4 to not recover locks after they are
    lost. (bnc#828236)

  - nfs: Adapt readdirplus to application usage patterns.
    (bnc#834708)

  - xfs: Account log unmount transaction correctly.
    (bnc#849950)

  - xfs: improve ioend error handling. (bnc#846036)

  - xfs: reduce ioend latency. (bnc#846036)

  - xfs: use per-filesystem I/O completion workqueues.
    (bnc#846036)

  - xfs: Hide additional entries in struct xfs_mount.
    (bnc#846036 / bnc#848544)

  - vfs: avoid 'attempt to access beyond end of device'
    warnings. (bnc#820338)

  - vfs: fix O_DIRECT read past end of block device.
    (bnc#820338)

  - cifs: Improve performance of browsing directories with
    several files. (bnc#810323)

  - cifs: Ensure cifs directories do not show up as files.
    (bnc#826602)

  - sd: avoid deadlocks when running under multipath.
    (bnc#818545)

  - sd: fix crash when UA received on DIF enabled device.
    (bnc#841445)

  - sg: fix blk_get_queue usage. (bnc#834808)

  - block: factor out vector mergeable decision to a helper
    function. (bnc#769644)

  - block: modify __bio_add_page check to accept pages that
    do not start a new segment. (bnc#769644)

  - dm-multipath: abort all requests when failing a path.
    (bnc#798050)

  - scsi: Add 'eh_deadline' to limit SCSI EH runtime.
    (bnc#798050)

  - scsi: Allow error handling timeout to be specified.
    (bnc#798050)

  - scsi: Fixup compilation warning. (bnc#798050)

  - scsi: Retry failfast commands after EH. (bnc#798050)

  - scsi: Warn on invalid command completion. (bnc#798050)

  - scsi: kABI fixes. (bnc#798050)

  - scsi: remove check for 'resetting'. (bnc#798050)

  - advansys: Remove 'last_reset' references. (bnc#798050)

  - cleanup setting task state in scsi_error_handler().
    (bnc#798050)

  - dc395: Move 'last_reset' into internal host structure.
    (bnc#798050)

  - dpt_i2o: Remove DPTI_STATE_IOCTL. (bnc#798050)

  - dpt_i2o: return SCSI_MLQUEUE_HOST_BUSY when in reset.
    (bnc#798050)

  - tmscsim: Move 'last_reset' into host structure.
    (bnc#798050)

  - scsi_dh: invoke callback if ->activate is not present.
    (bnc#708296)

  - scsi_dh: return individual errors in scsi_dh_activate().
    (bnc#708296)

  - scsi_dh_alua: Decode EMC Clariion extended inquiry.
    (bnc#708296)

  - scsi_dh_alua: Decode HP EVA array identifier.
    (bnc#708296)

  - scsi_dh_alua: Evaluate state for all port groups.
    (bnc#708296)

  - scsi_dh_alua: Fix missing close brace in
    alua_check_sense. (bnc#843642)

  - scsi_dh_alua: Make stpg synchronous. (bnc#708296)

  - scsi_dh_alua: Pass buffer as function argument.
    (bnc#708296)

  - scsi_dh_alua: Re-evaluate port group states after STPG.
    (bnc#708296)

  - scsi_dh_alua: Recheck state on transitioning.
    (bnc#708296)

  - scsi_dh_alua: Rework rtpg workqueue. (bnc#708296)

  - scsi_dh_alua: Use separate alua_port_group structure.
    (bnc#708296)

  - scsi_dh_alua: Allow get_alua_data() to return NULL.
    (bnc#839407)

  - scsi_dh_alua: asynchronous RTPG. (bnc#708296)

  - scsi_dh_alua: correctly terminate target port strings.
    (bnc#708296)

  - scsi_dh_alua: defer I/O while workqueue item is pending.
    (bnc#708296)

  - scsi_dh_alua: Do not attach to RAID or enclosure
    devices. (bnc#819979)

  - scsi_dh_alua: Do not attach to well-known LUNs.
    (bnc#821980)

  - scsi_dh_alua: fine-grained locking in alua_rtpg_work().
    (bnc#708296)

  - scsi_dh_alua: invalid state information for 'optimized'
    paths. (bnc#843445)

  - scsi_dh_alua: move RTPG to workqueue. (bnc#708296)

  - scsi_dh_alua: move 'expiry' into PG structure.
    (bnc#708296)

  - scsi_dh_alua: move some sense code handling into generic
    code. (bnc#813245)

  - scsi_dh_alua: multipath failover fails with error 15.
    (bnc#825696)

  - scsi_dh_alua: parse target device id. (bnc#708296)

  - scsi_dh_alua: protect accesses to struct
    alua_port_group. (bnc#708296)

  - scsi_dh_alua: put sense buffer on stack. (bnc#708296)

  - scsi_dh_alua: reattaching device handler fails with
    'Error 15'. (bnc#843429)

  - scsi_dh_alua: remove locking when checking state.
    (bnc#708296)

  - scsi_dh_alua: remove stale variable. (bnc#708296)

  - scsi_dh_alua: retry RTPG on UNIT ATTENTION. (bnc#708296)

  - scsi_dh_alua: retry command on 'mode parameter changed'
    sense code. (bnc#843645)

  - scsi_dh_alua: simplify alua_check_sense(). (bnc#843642)

  - scsi_dh_alua: simplify state update. (bnc#708296)

  - scsi_dh_alua: use delayed_work. (bnc#708296)

  - scsi_dh_alua: use flag for RTPG extended header.
    (bnc#708296)

  - scsi_dh_alua: use local buffer for VPD inquiry.
    (bnc#708296)

  - scsi_dh_alua: use spin_lock_irqsave for port group.
    (bnc#708296)

  - lpfc: Do not free original IOCB whenever ABTS fails.
    (bnc#806988)

  - lpfc: Fix kernel warning on spinlock usage. (bnc#806988)

  - lpfc: Fixed system panic due to midlayer abort.
    (bnc#806988)

  - qla2xxx: Add module parameter to override the default
    request queue size. (bnc#826756)

  - qla2xxx: Module parameter 'ql2xasynclogin'. (bnc#825896)

  - bna: do not register ndo_set_rx_mode callback.
    (bnc#847261)

  - hv: handle more than just WS2008 in KVP negotiation.
    (bnc#850640)

  - drm: do not add inferred modes for monitors that do not
    support them. (bnc#849809)

  - pci/quirks: Modify reset method for Chelsio T4.
    (bnc#831168)

  - pci: fix truncation of resource size to 32 bits.
    (bnc#843419)

  - pci: pciehp: Retrieve link speed after link is trained.
    (bnc#820102)

  - pci: Separate pci_bus_read_dev_vendor_id from
    pci_scan_device. (bnc#820102)

  - pci: pciehp: replace unconditional sleep with config
    space access check. (bnc#820102)

  - pci: pciehp: make check_link_active more helpful.
    (bnc#820102)

  - pci: pciehp: Add pcie_wait_link_not_active().
    (bnc#820102)

  - pci: pciehp: Add Disable/enable link functions.
    (bnc#820102)

  - pci: pciehp: Disable/enable link during slot power
    off/on. (bnc#820102)

  - mlx4: allocate just enough pages instead of always 4
    pages. (bnc#835186 / bnc#835074)

  - mlx4: allow order-0 memory allocations in RX path.
    (bnc#835186 / bnc#835074)

  - net/mlx4: use one page fragment per incoming frame.
    (bnc#835186 / bnc#835074)

  - qeth: request length checking in snmp ioctl (bnc#849848,
    LTC#99511).

  - cio: add message for timeouts on internal I/O
    (bnc#837739,LTC#97047).

  - s390/cio: dont abort verification after missing irq
    (bnc#837739,LTC#97047).

  - s390/cio: skip broken paths (bnc#837739,LTC#97047).

  - s390/cio: export vpm via sysfs (bnc#837739,LTC#97047).

  - s390/cio: handle unknown pgroup state
    (bnc#837739,LTC#97047)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=708296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=787843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=798050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=810323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=826602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=826756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834473"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=835074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=835186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=836718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=837739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=838623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=839407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=841445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=845621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=845729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=846036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=846984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=847261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=848321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=848336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=848544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=848652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=850640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=851066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=851101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=851314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=855037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4345.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4483.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4514.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4515.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4587.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4592.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6367.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6368.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6378.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6380.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6383.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6463.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7027.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8779 / 8791 / 8792 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/28");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-base-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-devel-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-extra-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-extra-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-source-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-syms-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-base-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-devel-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-extra-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-extra-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-kmp-default-4.1.6_04_3.0.101_0.7.15-0.5.12")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-kmp-pae-4.1.6_04_3.0.101_0.7.15-0.5.12")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-kmp-trace-4.1.6_04_3.0.101_0.7.15-0.5.12")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-base-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-devel-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-extra-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-source-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-syms-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-base-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-extra-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.6_04_3.0.101_0.7.15-0.5.12")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.6_04_3.0.101_0.7.15-0.5.12")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-base-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-devel-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-source-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-syms-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-base-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-devel-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-kmp-default-4.1.6_04_3.0.101_0.7.15-0.5.12")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-kmp-pae-4.1.6_04_3.0.101_0.7.15-0.5.12")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-kmp-trace-4.1.6_04_3.0.101_0.7.15-0.5.12")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-default-man-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.7.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.6_04_3.0.101_0.7.15-0.5.12")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.6_04_3.0.101_0.7.15-0.5.12")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
