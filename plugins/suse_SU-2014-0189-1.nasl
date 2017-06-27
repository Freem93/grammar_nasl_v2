#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:0189-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83609);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2013-2146", "CVE-2013-2930", "CVE-2013-4345", "CVE-2013-4483", "CVE-2013-4511", "CVE-2013-4514", "CVE-2013-4515", "CVE-2013-4587", "CVE-2013-4592", "CVE-2013-6367", "CVE-2013-6368", "CVE-2013-6376", "CVE-2013-6378", "CVE-2013-6380", "CVE-2013-6383", "CVE-2013-6463", "CVE-2013-7027");
  script_bugtraq_id(60324, 62740, 63445, 63509, 63512, 63518, 63790, 63886, 63887, 63888, 64013, 64270, 64291, 64318, 64319, 64328, 64669, 64739, 64741, 64742, 64743, 64744, 64746);
  script_osvdb_id(93906, 98017, 99161, 99326, 99327, 99674, 99675, 100002, 100292, 100294, 100296, 100505, 100506, 100984, 100985, 100986, 100987, 101656, 101804, 101805, 101806);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : kernel (SUSE-SU-2014:0189-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 3 kernel was updated to
3.0.101 and also includes various other bug and security fixes.

A new feature was added :

  - supported.conf: marked net/netfilter/xt_set as supported
    (bnc#851066)(fate#313309)

The following security bugs have been fixed :

CVE-2013-4587: Array index error in the kvm_vm_ioctl_create_vcpu
function in virt/kvm/kvm_main.c in the KVM subsystem in the Linux
kernel through 3.12.5 allows local users to gain privileges via a
large id value. (bnc#853050)

CVE-2013-4592: Memory leak in the __kvm_set_memory_region
function in virt/kvm/kvm_main.c in the Linux kernel before
3.9 allows local users to cause a denial of service (memory
consumption) by leveraging certain device access to trigger
movement of memory slots. (bnc#851101)

CVE-2013-6367: The apic_get_tmcct function in
arch/x86/kvm/lapic.c in the KVM subsystem in the Linux
kernel through 3.12.5 allows guest OS users to cause a
denial of service (divide-by-zero error and host OS crash)
via crafted modifications of the TMICT value. (bnc#853051)

CVE-2013-6368: The KVM subsystem in the Linux kernel through
3.12.5 allows local users to gain privileges or cause a
denial of service (system crash) via a VAPIC synchronization
operation involving a page-end address. (bnc#853052)

CVE-2013-6376: The recalculate_apic_map function in
arch/x86/kvm/lapic.c in the KVM subsystem in the Linux
kernel through 3.12.5 allows guest OS users to cause a
denial of service (host OS crash) via a crafted ICR write
operation in x2apic mode. (bnc#853053)

CVE-2013-4483: The ipc_rcu_putref function in ipc/util.c in
the Linux kernel before 3.10 does not properly manage a
reference count, which allows local users to cause a denial
of service (memory consumption or system crash) via a
crafted application. (bnc#848321)

CVE-2013-4511: Multiple integer overflows in Alchemy LCD
frame-buffer drivers in the Linux kernel before 3.12 allow
local users to create a read-write memory mapping for the
entirety of kernel memory, and consequently gain privileges,
via crafted mmap operations, related to the (1)
au1100fb_fb_mmap function in drivers/video/au1100fb.c and
the (2) au1200fb_fb_mmap function in
drivers/video/au1200fb.c. (bnc#849021)

CVE-2013-4514: Multiple buffer overflows in
drivers/staging/wlags49_h2/wl_priv.c in the Linux kernel
before 3.12 allow local users to cause a denial of service
or possibly have unspecified other impact by leveraging the
CAP_NET_ADMIN capability and providing a long station-name
string, related to the (1) wvlan_uil_put_info and (2)
wvlan_set_station_nickname functions. (bnc#849029)

CVE-2013-4515: The bcm_char_ioctl function in
drivers/staging/bcm/Bcmchar.c in the Linux kernel before
3.12 does not initialize a certain data structure, which
allows local users to obtain sensitive information from
kernel memory via an IOCTL_BCM_GET_DEVICE_DRIVER_INFO ioctl
call. (bnc#849034)

CVE-2013-6378: The lbs_debugfs_write function in
drivers/net/wireless/libertas/debugfs.c in the Linux kernel
through 3.12.1 allows local users to cause a denial of
service (OOPS) by leveraging root privileges for a
zero-length write operation. (bnc#852559)

CVE-2013-6380: The aac_send_raw_srb function in
drivers/scsi/aacraid/commctrl.c in the Linux kernel through
3.12.1 does not properly validate a certain size value,
which allows local users to cause a denial of service
(invalid pointer dereference) or possibly have unspecified
other impact via an FSACTL_SEND_RAW_SRB ioctl call that
triggers a crafted SRB command. (bnc#852373)

CVE-2013-7027: The ieee80211_radiotap_iterator_init function
in net/wireless/radiotap.c in the Linux kernel before 3.11.7
does not check whether a frame contains any data outside of
the header, which might allow attackers to cause a denial of
service (buffer over-read) via a crafted header.
(bnc#854634)

CVE-2013-6463: Linux kernel built with the networking
support(CONFIG_NET) is vulnerable to an information leakage
flaw in the socket layer. It could occur while doing
recvmsg(2), recvfrom(2) socket calls. It occurs due to
improperly initialised msg_name & msg_namelen message header
parameters. (bnc#854722)

CVE-2013-6383: The aac_compat_ioctl function in
drivers/scsi/aacraid/linit.c in the Linux kernel before
3.11.8 does not require the CAP_SYS_RAWIO capability, which
allows local users to bypass intended access restrictions
via a crafted ioctl call. (bnc#852558)

CVE-2013-4345: Off-by-one error in the get_prng_bytes
function in crypto/ansi_cprng.c in the Linux kernel through
3.11.4 makes it easier for context-dependent attackers to
defeat cryptographic protection mechanisms via multiple
requests for small amounts of data, leading to improper
management of the state of the consumed data. (bnc#840226)

CVE-2013-2146: arch/x86/kernel/cpu/perf_event_intel.c in the
Linux kernel before 3.8.9, when the Performance Events
Subsystem is enabled, specifies an incorrect bitmask, which
allows local users to cause a denial of service (general
protection fault and system crash) by attempting to set a
reserved bit. (bnc#825006)

CVE-2013-2930: The perf_trace_event_perm function in
kernel/trace/trace_event_perf.c in the Linux kernel before
3.12.2 does not properly restrict access to the perf
subsystem, which allows local users to enable function
tracing via a crafted application. (bnc#849362)

Also the following non-security bugs have been fixed :

  - kernel: correct tlb flush on page table upgrade
    (bnc#847660, LTC#99268).

  - kernel: fix floating-point-control register save and
    restore (bnc#847660, LTC#99000). kernel: correct
    handling of asce-type exceptions (bnc#851879,
    LTC#100293).

    watchdog: Get rid of MODULE_ALIAS_MISCDEV statements
    (bnc#827767).

  - random: fix accounting race condition with lockless irq
    entropy_count update (bnc#789359).

  - blktrace: Send BLK_TN_PROCESS events to all running
    traces (bnc#838623).

  - printk: forcibly flush nmi ringbuffer if oops is in
    progress (bnc#849675).

  - Introduce KABI exception for cpuidle_state->disable via
    #ifndef __GENKSYMS__

  - Honor state disabling in the cpuidle ladder governor
    (bnc#845378).

  - cpuidle: add a sysfs entry to disable specific C state
    for debug purpose (bnc#845378).

  - net: Do not enable tx-nocache-copy by default
    (bnc#845378).

  - mm: reschedule to avoid RCU stall triggering during boot
    of large machines (bnc#820434,bnc#852153). rtc-cmos: Add
    an alarm disable quirk (bnc#805740).

    tty/hvc_iucv: Disconnect IUCV connection when lowering
    DTR (bnc#839973, LTC#97595).

    tty/hvc_console: Add DTR/RTS callback to handle HUPCL
    control (bnc#839973, LTC#97595).

    sched: Avoid throttle_cfs_rq() racing with period_timer
    stopping (bnc#848336).

  - sched/balancing: Periodically decay max cost of idle
    balance (bnc#849256).

  - sched: Consider max cost of idle balance per sched
    domain (bnc#849256).

  - sched: Reduce overestimating rq->avg_idle (bnc#849256).

  - sched: Fix cfs_bandwidth misuse of
    hrtimer_expires_remaining (bnc#848336).

  - sched: Fix hrtimer_cancel()/rq->lock deadlock
    (bnc#848336).

  - sched: Fix race on toggling cfs_bandwidth_used
    (bnc#848336).

  - sched: Guarantee new group-entities always have weight
    (bnc#848336).

  - sched: Use jump labels to reduce overhead when bandwidth
    control is inactive (bnc#848336). sched: Fix several
    races in CFS_BANDWIDTH (bnc#848336).

    futex: fix handling of read-only-mapped hugepages (VM
    Functionality).

  - futex: move user address verification up to common code
    (bnc#851603).

  - futexes: Clean up various details (bnc#851603).

  - futexes: Increase hash table size for better performance
    (bnc#851603).

  - futexes: Document multiprocessor ordering guarantees
    (bnc#851603).

  - futexes: Avoid taking the hb->lock if there is nothing
    to wake up (bnc#851603).

  - futexes: Fix futex_hashsize initialization (bnc#851603).
    mutex: Make more scalable by doing fewer atomic
    operations (bnc#849256).

    powerpc: Fix memory hotplug with sparse vmemmap
    (bnc#827527).

  - powerpc: Add System RAM to /proc/iomem (bnc#827527).

  - powerpc/mm: Mark Memory Resources as busy (bnc#827527).

  - powerpc: Fix fatal SLB miss when restoring PPR
    (bnc#853465).

  - powerpc: Make function that parses RTAS error logs
    global (bnc#852761).

  - powerpc/pseries: Parse and handle EPOW interrupts
    (bnc#852761).

  - powerpc/rtas_flash: Fix validate_flash buffer overflow
    issue (bnc#847842). powerpc/rtas_flash: Fix bad memory
    access (bnc#847842).

    x86: Update UV3 hub revision ID (bnc#846298
    fate#314987).

  - x86: Remove some noise from boot log when starting cpus
    (bnc#770541).

  - x86/microcode/amd: Tone down printk(), do not treat a
    missing firmware file as an error (bnc#843654).

  - x86/dumpstack: Fix printk_address for direct addresses
    (bnc#845621). x86/PCI: reduce severity of host bridge
    window conflict warnings (bnc#858534).

    ipv6: fix race condition regarding dst->expires and
    dst->from (bnc#843185).

  - netback: bump tx queue length (bnc#849404).

  - xfrm: invalidate dst on policy insertion/deletion
    (bnc#842239). xfrm: prevent ipcomp scratch buffer race
    condition (bnc#842239).

    tcp: bind() fix autoselection to share ports
    (bnc#823618).

  - tcp: bind() use stronger condition for bind_conflict
    (bnc#823618).

  - tcp: ipv6: bind() use stronger condition for
    bind_conflict (bnc#823618). kabi: protect bind_conflict
    callback in struct inet_connection_sock_af_ops
    (bnc#823618).

    macvlan: introduce IFF_MACVLAN flag and helper function
    (bnc#846984).

  - macvlan: introduce macvlan_dev_real_dev() helper
    function (bnc#846984). macvlan: disable LRO on lower
    device instead of macvlan (bnc#846984).

    fs: Avoid softlockup in shrink_dcache_for_umount_subtree
    (bnc#834473).

  - blkdev_max_block: make private to fs/buffer.c
    (bnc#820338). storage: SMI Corporation usb key added to
    READ_CAPACITY_10 quirk (bnc#850324).

    autofs4: autofs4_wait() vs. autofs4_catatonic_mode()
    race (bnc#851314).

  - autofs4: catatonic_mode vs. notify_daemon race
    (bnc#851314).

  - autofs4: close the races around autofs4_notify_daemon()
    (bnc#851314).

  - autofs4: deal with autofs4_write/autofs4_write races
    (bnc#851314).

  - autofs4: dont clear DCACHE_NEED_AUTOMOUNT on rootless
    mount (bnc#851314).

  - autofs4: fix deal with autofs4_write races (bnc#851314).
    autofs4: use simple_empty() for empty directory check
    (bnc#851314).

    dlm: set zero linger time on sctp socket (bnc#787843).

  - SUNRPC: Fix a data corruption issue when retransmitting
    RPC calls (no bugzilla yet - netapp confirms problem and
    fix).

  - nfs: Change NFSv4 to not recover locks after they are
    lost (bnc#828236). nfs: Adapt readdirplus to application
    usage patterns (bnc#834708).

    xfs: Account log unmount transaction correctly
    (bnc#849950).

  - xfs: improve ioend error handling (bnc#846036).

  - xfs: reduce ioend latency (bnc#846036).

  - xfs: use per-filesystem I/O completion workqueues
    (bnc#846036). xfs: Hide additional entries in struct
    xfs_mount (bnc#846036 bnc#848544).

    Btrfs: do not BUG_ON() if we get an error walking
    backrefs (FATE#312888).

    vfs: avoid 'attempt to access beyond end of device'
    warnings (bnc#820338).

  - vfs: fix O_DIRECT read past end of block device
    (bnc#820338).

  - cifs: Improve performance of browsing directories with
    several files (bnc#810323). cifs: Ensure cifs
    directories do not show up as files (bnc#826602).

    dm-multipath: abort all requests when failing a path
    (bnc#798050).

  - scsi: Add 'eh_deadline' to limit SCSI EH runtime
    (bnc#798050).

  - scsi: Allow error handling timeout to be specified
    (bnc#798050).

  - scsi: Fixup compilation warning (bnc#798050).

  - scsi: Retry failfast commands after EH (bnc#798050).

  - scsi: Warn on invalid command completion (bnc#798050).

  - advansys: Remove 'last_reset' references (bnc#798050).

  - cleanup setting task state in scsi_error_handler()
    (bnc#798050).

  - dc395: Move 'last_reset' into internal host structure
    (bnc#798050).

  - dpt_i2o: Remove DPTI_STATE_IOCTL (bnc#798050).

  - dpt_i2o: return SCSI_MLQUEUE_HOST_BUSY when in reset
    (bnc#798050).

  - scsi: kABI fixes (bnc#798050).

  - scsi: remove check for 'resetting' (bnc#798050).
    tmscsim: Move 'last_reset' into host structure
    (bnc#798050).

    SCSI & usb-storage: add try_rc_10_first flag
    (bnc#853428).

  - iscsi_target: race condition on shutdown (bnc#850072).

  - libfcoe: Make fcoe_sysfs optional / fix fnic NULL
    exception (bnc#837206).

  - lpfc 8.3.42: Fixed issue of task management commands
    having a fixed timeout (bnc#856481).

  - advansys: Remove 'last_reset' references (bnc#856481).

  - dc395: Move 'last_reset' into internal host structure
    (bnc#856481).

  - Add 'eh_deadline' to limit SCSI EH runtime (bnc#856481).

  - remove check for 'resetting' (bnc#856481). tmscsim: Move
    'last_reset' into host structure (bnc#856481).

    scsi_dh_rdac: Add new IBM 1813 product id to rdac
    devlist (bnc#846654).

    md: Change handling of save_raid_disk and metadata
    update during recovery (bnc#849364).

    dpt_i2o: Remove DPTI_STATE_IOCTL (bnc#856481).

    dpt_i2o: return SCSI_MLQUEUE_HOST_BUSY when in reset
    (bnc#856481).

    crypto: unload of aes_s390 module causes kernel panic
    (bnc#847660, LTC#98706).

  - crypto: Fix aes-xts parameter corruption (bnc#854546,
    LTC#100718). crypto: gf128mul - fix call to memset()
    (obvious fix).

    X.509: Fix certificate gathering (bnc#805114).

    pcifront: Deal with toolstack missing
    'XenbusStateClosing' state.

  - xencons: generalize use of add_preferred_console()
    (bnc#733022, bnc#852652).

  - netxen: fix off by one bug in netxen_release_tx_buffer()
    (bnc#845729).

  - xen: xen_spin_kick fixed crash/lock release
    (bnc#807434)(bnc#848652). xen: fixed USB passthrough
    issue (bnc#852624).

    igb: Fix get_fw_version function for all parts
    (bnc#848317).

  - igb: Refactor of init_nvm_params (bnc#848317).

  - r8169: check ALDPS bit and disable it if enabled for the
    8168g (bnc#845352).

  - qeth: request length checking in snmp ioctl (bnc#847660,
    LTC#99511). bnx2x: remove false warning regarding
    interrupt number (bnc#769035).

    usb: Fix xHCI host issues on remote wakeup (bnc#846989).

  - xhci: Limit the spurious wakeup fix only to HP machines
    (bnc#833097).

  - Intel xhci: refactor EHCI/xHCI port switching
    (bnc#840116).

  - xhci-hub.c: preserved kABI (bnc#840116). xhci: Refactor
    port status into a new function (bnc#840116).

    HID: multitouch: Add support for NextWindow 0340
    touchscreen (bnc#849855).

  - HID: multitouch: Add support for Qaunta 3027 touchscreen
    (bnc#854516).

  - HID: multitouch: add support for Atmel 212c touchscreen
    (bnc#793727).

  - HID: multitouch: partial support of win8 devices
    (bnc#854516,bnc#793727,bnc#849855). HID: hid-multitouch:
    add support for the IDEACOM 6650 chip
    (bnc#854516,bnc#793727,bnc#849855).

    ALSA: hda - Fix inconsistent mic-mute LED (bnc#848864).

    ALSA: hda - load EQ params into IDT codec on HP bNB13
    systems (bnc#850493).

    lpfc: correct some issues with txcomplq processing
    (bnc#818064).

    lpfc: correct an issue with rrq processing (bnc#818064).

    block: factor out vector mergeable decision to a helper
    function (bnc#769644).

    block: modify __bio_add_page check to accept pages that
    do not start a new segment (bnc#769644).

    sd: avoid deadlocks when running under multipath
    (bnc#818545).

  - sd: fix crash when UA received on DIF enabled device
    (bnc#841445). sg: fix blk_get_queue usage (bnc#834808).

    lpfc: Do not free original IOCB whenever ABTS fails
    (bnc#806988).

  - lpfc: Fix kernel warning on spinlock usage (bnc#806988).
    lpfc: Fixed system panic due to midlayer abort
    (bnc#806988).

    qla2xxx: Add module parameter to override the default
    request queue size (bnc#826756).

    qla2xxx: Module parameter 'ql2xasynclogin' (bnc#825896).

    Pragmatic workaround for realtime class abuse induced
    latency issues.

    Provide realtime priority kthread and workqueue boot
    options (bnc#836718).

    mlx4: allocate just enough pages instead of always 4
    pages (bnc#835186 bnc#835074).

  - mlx4: allow order-0 memory allocations in RX path
    (bnc#835186 bnc#835074).

  - net/mlx4: use one page fragment per incoming frame
    (bnc#835186 bnc#835074). bna: do not register
    ndo_set_rx_mode callback (bnc#847261).

    PCI: pciehp: Retrieve link speed after link is trained
    (bnc#820102).

  - PCI: Separate pci_bus_read_dev_vendor_id from
    pci_scan_device (bnc#820102).

  - PCI: pciehp: replace unconditional sleep with config
    space access check (bnc#820102).

  - PCI: pciehp: make check_link_active more helpful
    (bnc#820102).

  - PCI: pciehp: Add pcie_wait_link_not_active()
    (bnc#820102).

  - PCI: pciehp: Add Disable/enable link functions
    (bnc#820102).

  - PCI: pciehp: Disable/enable link during slot power
    off/on (bnc#820102). PCI: fix truncation of resource
    size to 32 bits (bnc#843419).

    hv: handle more than just WS2008 in KVP negotiation
    (bnc#850640).

    mei: ME hardware reset needs to be synchronized
    (bnc#821619).

    kabi: Restore struct irq_desc::timer_rand_state.

    fs3270: unloading module does not remove device
    (bnc#851879, LTC#100284).

    cio: add message for timeouts on internal I/O
    (bnc#837739,LTC#97047).

    isci: Fix a race condition in the SSP task management
    path (bnc#826978).

    ptp: dynamic allocation of PHC char devices
    (bnc#851290).

    efifb: prevent null-deref when iterating dmi_list
    (bnc#848055).

    dm-mpath: Fixup race condition in activate_path()
    (bnc#708296).

  - dm-mpath: do not detach stale hardware handler
    (bnc#708296). dm-multipath: Improve logging
    (bnc#708296).

    scsi_dh: invoke callback if ->activate is not present
    (bnc#708296).

  - scsi_dh: return individual errors in scsi_dh_activate()
    (bnc#708296).

  - scsi_dh_alua: Decode EMC Clariion extended inquiry
    (bnc#708296).

  - scsi_dh_alua: Decode HP EVA array identifier
    (bnc#708296).

  - scsi_dh_alua: Evaluate state for all port groups
    (bnc#708296).

  - scsi_dh_alua: Fix missing close brace in
    alua_check_sense (bnc#843642).

  - scsi_dh_alua: Make stpg synchronous (bnc#708296).

  - scsi_dh_alua: Pass buffer as function argument
    (bnc#708296).

  - scsi_dh_alua: Re-evaluate port group states after STPG
    (bnc#708296).

  - scsi_dh_alua: Recheck state on transitioning
    (bnc#708296).

  - scsi_dh_alua: Rework rtpg workqueue (bnc#708296).

  - scsi_dh_alua: Use separate alua_port_group structure
    (bnc#708296).

  - scsi_dh_alua: Allow get_alua_data() to return NULL
    (bnc#839407).

  - scsi_dh_alua: asynchronous RTPG (bnc#708296).

  - scsi_dh_alua: correctly terminate target port strings
    (bnc#708296).

  - scsi_dh_alua: defer I/O while workqueue item is pending
    (bnc#708296).

  - scsi_dh_alua: Do not attach to RAID or enclosure devices
    (bnc#819979).

  - scsi_dh_alua: Do not attach to well-known LUNs
    (bnc#821980).

  - scsi_dh_alua: fine-grained locking in alua_rtpg_work()
    (bnc#708296).

  - scsi_dh_alua: invalid state information for 'optimized'
    paths (bnc#843445).

  - scsi_dh_alua: move RTPG to workqueue (bnc#708296).

  - scsi_dh_alua: move 'expiry' into PG structure
    (bnc#708296).

  - scsi_dh_alua: move some sense code handling into generic
    code (bnc#813245).

  - scsi_dh_alua: multipath failover fails with error 15
    (bnc#825696).

  - scsi_dh_alua: parse target device id (bnc#708296).

  - scsi_dh_alua: protect accesses to struct alua_port_group
    (bnc#708296).

  - scsi_dh_alua: put sense buffer on stack (bnc#708296).

  - scsi_dh_alua: reattaching device handler fails with
    'Error 15' (bnc#843429).

  - scsi_dh_alua: remove locking when checking state
    (bnc#708296).

  - scsi_dh_alua: remove stale variable (bnc#708296).

  - scsi_dh_alua: retry RTPG on UNIT ATTENTION (bnc#708296).

  - scsi_dh_alua: retry command on 'mode parameter changed'
    sense code (bnc#843645).

  - scsi_dh_alua: simplify alua_check_sense() (bnc#843642).

  - scsi_dh_alua: simplify state update (bnc#708296).

  - scsi_dh_alua: use delayed_work (bnc#708296).

  - scsi_dh_alua: use flag for RTPG extended header
    (bnc#708296).

  - scsi_dh_alua: use local buffer for VPD inquiry
    (bnc#708296).

  - scsi_dh_alua: use spin_lock_irqsave for port group
    (bnc#708296).

  - scsi_dh_alua: defer I/O while workqueue item is pending
    (bnc#708296).

  - scsi_dh_alua: Rework rtpg workqueue (bnc#708296).

  - scsi_dh_alua: use delayed_work (bnc#708296).

  - scsi_dh_alua: move 'expiry' into PG structure
    (bnc#708296).

  - scsi_dh: invoke callback if ->activate is not present
    (bnc#708296).

  - scsi_dh_alua: correctly terminate target port strings
    (bnc#708296).

  - scsi_dh_alua: retry RTPG on UNIT ATTENTION (bnc#708296).

  - scsi_dh_alua: protect accesses to struct alua_port_group
    (bnc#708296).

  - scsi_dh_alua: fine-grained locking in alua_rtpg_work()
    (bnc#708296).

  - scsi_dh_alua: use spin_lock_irqsave for port group
    (bnc#708296).

  - scsi_dh_alua: remove locking when checking state
    (bnc#708296).

  - scsi_dh_alua: remove stale variable (bnc#708296).

  - scsi_dh: return individual errors in scsi_dh_activate()
    (bnc#708296). scsi_dh_alua: fixup misplaced brace in
    alua_initialize() (bnc#858831).

    drm/i915: add I915_PARAM_HAS_VEBOX to i915_getparam
    (bnc#831103,FATE#316109).

  - drm/i915: add I915_EXEC_VEBOX to
    i915_gem_do_execbuffer() (bnc#831103,FATE#316109).

  - drm/i915: add VEBOX into debugfs
    (bnc#831103,FATE#316109).

  - drm/i915: Enable vebox interrupts
    (bnc#831103,FATE#316109).

  - drm/i915: vebox interrupt get/put
    (bnc#831103,FATE#316109).

  - drm/i915: consolidate interrupt naming scheme
    (bnc#831103,FATE#316109).

  - drm/i915: Convert irq_refounct to struct
    (bnc#831103,FATE#316109).

  - drm/i915: make PM interrupt writes non-destructive
    (bnc#831103,FATE#316109).

  - drm/i915: Add PM regs to pre/post install
    (bnc#831103,FATE#316109).

  - drm/i915: Create an ivybridge_irq_preinstall
    (bnc#831103,FATE#316109).

  - drm/i915: Create a more generic pm handler for hsw+
    (bnc#831103,FATE#316109).

  - drm/i915: Vebox ringbuffer init
    (bnc#831103,FATE#316109).

  - drm/i915: add HAS_VEBOX (bnc#831103,FATE#316109).

  - drm/i915: Rename ring flush functions
    (bnc#831103,FATE#316109).

  - drm/i915: Add VECS semaphore bits
    (bnc#831103,FATE#316109).

  - drm/i915: Introduce VECS: the 4th ring
    (bnc#831103,FATE#316109).

  - drm/i915: Semaphore MBOX update generalization
    (bnc#831103,FATE#316109).

  - drm/i915: Comments for semaphore clarification
    (bnc#831103,FATE#316109).

  - drm/i915: fix gen4 digital port hotplug definitions
    (bnc#850103).

  - drm/mgag200: Bug fix: Modified pll algorithm for EH
    project (bnc#841654). drm: do not add inferred modes for
    monitors that do not support them (bnc #849809).

    s390/cio: dont abort verification after missing irq
    (bnc#837739,LTC#97047).

  - s390/cio: skip broken paths (bnc#837739,LTC#97047).

  - s390/cio: export vpm via sysfs (bnc#837739,LTC#97047).

  - s390/cio: handle unknown pgroup state
    (bnc#837739,LTC#97047).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.novell.com/patch/finder/?keywords=155ef3b4e3ba6228ccaef2cbc31bebd9
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?508af80c"
  );
  # http://download.novell.com/patch/finder/?keywords=5bc4480468b77bc708f1a53315eda1a5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41c59b1d"
  );
  # http://download.novell.com/patch/finder/?keywords=5bf653f731ed3521053f5341cf36caed
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81371f29"
  );
  # http://download.novell.com/patch/finder/?keywords=80a0fe93ee599f6907148b6d57bc4386
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2c10cd3"
  );
  # http://download.novell.com/patch/finder/?keywords=84ede2844b021edeba8226469dc99257
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4fd89842"
  );
  # http://download.novell.com/patch/finder/?keywords=8fce986182f7f5e181facfac1db4aae3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90e9ccc2"
  );
  # http://download.novell.com/patch/finder/?keywords=a863e6ada238d9cd2f9e9150d31fefff
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09a3fa7e"
  );
  # http://download.novell.com/patch/finder/?keywords=b711e9a5616f248e3074a4b6c9570dc5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a374681"
  );
  # http://download.novell.com/patch/finder/?keywords=d80e8135e5fe036068f832766fc4cfb9
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe789f30"
  );
  # http://download.novell.com/patch/finder/?keywords=ff3893b2e58671834b0dfa8fb9b43401
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c79cf66"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2146.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2930.html"
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
    value:"http://support.novell.com/security/cve/CVE-2013-6376.html"
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
    attribute:"see_also",
    value:"https://bugzilla.novell.com/708296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/733022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/769035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/769644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/770541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/787843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/789359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/793727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/798050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/805114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/805740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/806988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/807434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/810323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/813245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/818064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/818545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/819979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/820102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/820338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/820434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/821619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/821980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/823618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/825006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/825696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/825896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/826602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/826756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/826978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/827527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/827767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/828236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/831103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/833097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/834473"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/834708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/834808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/835074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/835186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/836718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/837206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/837739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/838623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/839407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/839973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/840116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/840226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/841445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/841654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/842239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/843185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/843419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/843429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/843445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/843642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/843645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/843654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/845352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/845378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/845621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/845729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/846036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/846298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/846654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/846984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/846989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/847261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/847660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/847842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/848055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/848317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/848321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/848335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/848336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/848544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/848652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/848864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/850072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/850103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/850324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/850493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/850640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/851066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/851101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/851290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/851314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/851603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/851879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/852153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/852373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/852558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/852559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/852624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/852652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/852761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/853050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/853051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/853052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/853053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/853428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/853465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/854516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/854546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/854634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/854722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/856307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/856481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/858534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/858831"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20140189-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0cc1610"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP3 for VMware :

zypper in -t patch slessp3-kernel-8823 slessp3-kernel-8827

SUSE Linux Enterprise Server 11 SP3 :

zypper in -t patch slessp3-kernel-8823 slessp3-kernel-8824
slessp3-kernel-8825 slessp3-kernel-8826 slessp3-kernel-8827

SUSE Linux Enterprise High Availability Extension 11 SP3 :

zypper in -t patch slehasp3-kernel-8823 slehasp3-kernel-8824
slehasp3-kernel-8825 slehasp3-kernel-8826 slehasp3-kernel-8827

SUSE Linux Enterprise Desktop 11 SP3 :

zypper in -t patch sledsp3-kernel-8823 sledsp3-kernel-8827

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^3$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^3$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-default-4.2.3_08_3.0.101_0.15-0.7.22")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-pae-4.2.3_08_3.0.101_0.15-0.7.22")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-base-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-devel-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-source-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-syms-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-base-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-devel-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-default-4.2.3_08_3.0.101_0.15-0.7.22")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-pae-4.2.3_08_3.0.101_0.15-0.7.22")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-base-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-devel-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-extra-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-source-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-syms-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-kmp-default-4.2.3_08_3.0.101_0.15-0.7.22")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-extra-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-kmp-pae-4.2.3_08_3.0.101_0.15-0.7.22")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-base-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-devel-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-extra-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-source-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-syms-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-trace-devel-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-extra-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-kmp-default-4.2.3_08_3.0.101_0.15-0.7.22")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-extra-3.0.101-0.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-kmp-pae-4.2.3_08_3.0.101_0.15-0.7.22")) flag++;


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
