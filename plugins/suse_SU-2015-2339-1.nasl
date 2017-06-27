#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2339-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87651);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2015-0272", "CVE-2015-5157", "CVE-2015-5307", "CVE-2015-6937", "CVE-2015-7509", "CVE-2015-7799", "CVE-2015-7872", "CVE-2015-7990", "CVE-2015-8104", "CVE-2015-8215");
  script_bugtraq_id(76005);
  script_osvdb_id(125208, 127518, 127759, 128845, 129330, 130089, 130090, 132202);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : kernel (SUSE-SU-2015:2339-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various
security and bugfixes.

Following security bugs were fixed :

  - CVE-2015-7509: Mounting ext4 filesystems in no-journal
    mode could hav lead to a system crash (bsc#956709).

  - CVE-2015-7799: The slhc_init function in
    drivers/net/slip/slhc.c in the Linux kernel did not
    ensure that certain slot numbers are valid, which
    allowed local users to cause a denial of service (NULL
    pointer dereference and system crash) via a crafted
    PPPIOCSMAXCID ioctl call (bnc#949936).

  - CVE-2015-8104: The KVM subsystem in the Linux kernel
    allowed guest OS users to cause a denial of service
    (host OS panic or hang) by triggering many #DB (aka
    Debug) exceptions, related to svm.c (bnc#954404).

  - CVE-2015-5307: The KVM subsystem in the Linux kernel
    allowed guest OS users to cause a denial of service
    (host OS panic or hang) by triggering many #AC (aka
    Alignment Check) exceptions, related to svm.c and vmx.c
    (bnc#953527).

  - CVE-2015-7990: RDS: There was no verification that an
    underlying transport exists when creating a connection,
    causing usage of a NULL pointer (bsc#952384).

  - CVE-2015-5157: arch/x86/entry/entry_64.S in the Linux
    kernel on the x86_64 platform mishandled IRET faults in
    processing NMIs that occurred during userspace
    execution, which might have allowed local users to gain
    privileges by triggering an NMI (bnc#938706).

  - CVE-2015-7872: The key_gc_unused_keys function in
    security/keys/gc.c in the Linux kernel allowed local
    users to cause a denial of service (OOPS) via crafted
    keyctl commands (bnc#951440).

  - CVE-2015-0272: Missing checks allowed remote attackers
    to cause a denial of service (IPv6 traffic disruption)
    via a crafted MTU value in an IPv6 Router Advertisement
    (RA) message, a different vulnerability than
    CVE-2015-8215 (bnc#944296).

  - CVE-2015-6937: The __rds_conn_create function in
    net/rds/connection.c in the Linux kernel allowed local
    users to cause a denial of service (NULL pointer
    dereference and system crash) or possibly have
    unspecified other impact by using a socket that was not
    properly bound (bnc#945825).

The following non-security bugs were fixed :

  - ALSA: hda - Disable 64bit address for Creative HDA
    controllers (bnc#814440).

  - Driver: Vmxnet3: Fix ethtool -S to return correct rx
    queue stats (bsc#950750).

  - Drivers: hv: do not do hypercalls when hypercall_page is
    NULL.

  - Drivers: hv: kvp: move poll_channel() to hyperv_vmbus.h.

  - Drivers: hv: util: move kvp/vss function declarations to
    hyperv_vmbus.h.

  - Drivers: hv: vmbus: Get rid of some unused definitions.

  - Drivers: hv: vmbus: Implement the protocol for tearing
    down vmbus state.

  - Drivers: hv: vmbus: add special crash handler
    (bnc#930770).

  - Drivers: hv: vmbus: add special kexec handler.

  - Drivers: hv: vmbus: kill tasklets on module unload.

  - Drivers: hv: vmbus: prefer '^A' notification chain to
    'panic'.

  - Drivers: hv: vmbus: remove hv_synic_free_cpu() call from
    hv_synic_cleanup().

  - Drivers: hv: vmbus: unregister panic notifier on module
    unload.

  - IB/srp: Avoid skipping srp_reset_host() after a
    transport error (bsc#904965).

  - IB/srp: Fix a sporadic crash triggered by cable pulling
    (bsc#904965).

  - KEYS: Fix race between key destruction and finding a
    keyring by name (bsc#951440).

  - Make sure XPRT_CONNECTING gets cleared when needed
    (bsc#946309).

  - NFSv4: Fix two infinite loops in the mount code
    (bsc#954628).

  - PCI: Add VPD function 0 quirk for Intel Ethernet devices
    (bnc#943786).

  - PCI: Add dev_flags bit to access VPD through function 0
    (bnc#943786).

  - PCI: Clear NumVFs when disabling SR-IOV in sriov_init()
    (bnc#952084).

  - PCI: Refresh First VF Offset and VF Stride when updating
    NumVFs (bnc#952084).

  - PCI: Update NumVFs register when disabling SR-IOV
    (bnc#952084).

  - PCI: delay configuration of SRIOV capability
    (bnc#952084).

  - PCI: set pci sriov page size before reading SRIOV BAR
    (bnc#952084).

  - SCSI: hosts: update to use ida_simple for host_no
    (bsc#939926)

  - SUNRPC refactor rpcauth_checkverf error returns
    (bsc#955673).

  - af_iucv: avoid path quiesce of severed path in
    shutdown() (bnc#946214).

  - ahci: Add Device ID for Intel Sunrise Point PCH
    (bsc#953799).

  - blktap: also call blkif_disconnect() when frontend
    switched to closed (bsc#952976).

  - blktap: refine mm tracking (bsc#952976).

  - cachefiles: Avoid deadlocks with fs freezing
    (bsc#935123).

  - dm sysfs: introduce ability to add writable attributes
    (bsc#904348).

  - dm-snap: avoid deadock on s->lock when a read is split
    (bsc#939826).

  - dm: do not start current request if it would've merged
    with the previous (bsc#904348).

  - dm: impose configurable deadline for dm_request_fn's
    merge heuristic (bsc#904348).

  - drm/i915: Avoid race of intel_crt_detect_hotplug() with
    HPD interrupt, v2 (bsc#942938).

  - drm/i915: Fix DDC probe for passive adapters
    (bsc#900610, fdo#85924).

  - drm/i915: add hotplug activation period to hotplug
    update mask (bsc#953980).

  - fix lpfc_send_rscn_event allocation size claims
    bnc#935757

  - fs: Avoid deadlocks of fsync_bdev() and fs freezing
    (bsc#935123).

  - fs: Fix deadlocks between sync and fs freezing
    (bsc#935123).

  - hugetlb: simplify migrate_huge_page() (bnc#947957).

  - hwpoison, hugetlb: lock_page/unlock_page does not match
    for handling a free hugepage (bnc#947957,).

  - ipr: Fix incorrect trace indexing (bsc#940913).

  - ipr: Fix invalid array indexing for HRRQ (bsc#940913).

  - ipv6: fix tunnel error handling (bsc#952579).

  - ipvs: Fix reuse connection if real server is dead
    (bnc#945827).

  - ipvs: drop first packet to dead server (bsc#946078).

  - kernel: correct uc_sigmask of the compat signal frame
    (bnc#946214).

  - kernel: fix incorrect use of DIAG44 in
    continue_trylock_relax() (bnc#946214).

  - kexec: Fix race between panic() and crash_kexec() called
    directly (bnc#937444).

  - ktime: add ktime_after and ktime_before helpe
    (bsc#904348).

  - lib/string.c: introduce memchr_inv() (bnc#930788).

  - lpfc: Fix cq_id masking problem (bsc#944677).

  - macvlan: Support bonding events bsc#948521

  - memory-failure: do code refactor of soft_offline_page()
    (bnc#947957).

  - memory-failure: fix an error of mce_bad_pages statistics
    (bnc#947957).

  - memory-failure: use num_poisoned_pages instead of
    mce_bad_pages (bnc#947957).

  - memory-hotplug: update mce_bad_pages when removing the
    memory (bnc#947957).

  - mm/memory-failure.c: fix wrong num_poisoned_pages in
    handling memory error on thp (bnc#947957).

  - mm/memory-failure.c: recheck PageHuge() after hugetlb
    page migrate successfully (bnc#947957).

  - mm/migrate.c: pair unlock_page() and lock_page() when
    migrating huge pages (bnc#947957).

  - mm: exclude reserved pages from dirtyable memory 32b fix
    (bnc#940017, bnc#949298).

  - mm: fix GFP_THISNODE callers and clarify (bsc#954950).

  - mm: remove GFP_THISNODE (bsc#954950).

  - mm: sl[au]b: add knowledge of PFMEMALLOC reserve pages
    (Swap over NFS).

  - net/core: Add VF link state control policy (bsc#950298).

  - netfilter: xt_recent: fix namespace destroy path
    (bsc#879378).

  - panic/x86: Allow cpus to save registers even if they
    (bnc#940946).

  - panic/x86: Fix re-entrance problem due to panic on
    (bnc#937444).

  - pktgen: clean up ktime_t helpers (bsc#904348).

  - qla2xxx: Do not reset adapter if SRB handle is in range
    (bsc#944993).

  - qla2xxx: Remove decrement of sp reference count in abort
    handler (bsc#944993).

  - qla2xxx: Remove unavailable firmware files (bsc#921081).

  - qla2xxx: do not clear slot in outstanding cmd array
    (bsc#944993).

  - qlge: Fix qlge_update_hw_vlan_features to handle if
    interface is down (bsc#930835).

  - quota: Fix deadlock with suspend and quotas
    (bsc#935123).

  - rcu: Eliminate deadlock between CPU hotplug and
    expedited grace periods (bsc#949706).

  - rtc: cmos: Cancel alarm timer if alarm time is equal to
    now+1 seconds (bsc#930145).

  - rtnetlink: Fix VF IFLA policy (bsc#950298).

  - rtnetlink: fix VF info size (bsc#950298).

  - s390/dasd: fix disconnected device with valid path mask
    (bnc#946214).

  - s390/dasd: fix invalid PAV assignment after
    suspend/resume (bnc#946214).

  - s390/dasd: fix list_del corruption after lcu changes
    (bnc#954984).

  - s390/pci: handle events for unused functions
    (bnc#946214).

  - s390/pci: improve handling of hotplug event 0x301
    (bnc#946214).

  - s390/pci: improve state check when processing hotplug
    events (bnc#946214).

  - sched/core: Fix task and run queue sched_info::run_delay
    inconsistencies (bnc#949100).

  - sg: fix read() error reporting (bsc#926774).

  - usb: xhci: apply XHCI_AVOID_BEI quirk to all Intel xHCI
    controllers (bnc#944989).

  - usbback: correct copy length for partial transfers
    (bsc#941202).

  - usbvision fix overflow of interfaces array (bnc#950998).

  - veth: extend device features (bsc#879381).

  - vfs: Provide function to get superblock and wait for it
    to thaw (bsc#935123).

  - vmxnet3: adjust ring sizes when interface is down
    (bsc#950750).

  - vmxnet3: fix ethtool ring buffer size setting
    (bsc#950750).

  - writeback: Skip writeback for frozen filesystem
    (bsc#935123).

  - x86, pageattr: Prevent overflow in slow_virt_to_phys()
    for X86_PAE (bnc#937256).

  - x86/evtchn: make use of PHYSDEVOP_map_pirq.

  - x86: mm: drop TLB flush from ptep_set_access_flags
    (bsc#948330).

  - x86: mm: only do a local tlb flush in
    ptep_set_access_flags() (bsc#948330).

  - xen: x86, pageattr: Prevent overflow in
    slow_virt_to_phys() for X86_PAE (bnc#937256).

  - xfs: Fix lost direct IO write in the last block
    (bsc#949744).

  - xfs: Fix softlockup in xfs_inode_ag_walk() (bsc#948347).

  - xfs: add EOFBLOCKS inode tagging/untagging (bnc#930788).

  - xfs: add XFS_IOC_FREE_EOFBLOCKS ioctl (bnc#930788).

  - xfs: add background scanning to clear eofblocks inodes
    (bnc#930788).

  - xfs: add inode id filtering to eofblocks scan
    (bnc#930788).

  - xfs: add minimum file size filtering to eofblocks scan
    (bnc#930788).

  - xfs: create function to scan and clear EOFBLOCKS inodes
    (bnc#930788).

  - xfs: create helper to check whether to free eofblocks on
    inode (bnc#930788).

  - xfs: introduce a common helper xfs_icluster_size_fsb
    (bsc#932805).

  - xfs: make xfs_free_eofblocks() non-static, return EAGAIN
    on trylock failure (bnc#930788).

  - xfs: support a tag-based inode_ag_iterator (bnc#930788).

  - xfs: support multiple inode id filtering in eofblocks
    scan (bnc#930788).

  - xfs: use xfs_icluster_size_fsb in xfs_bulkstat
    (bsc#932805).

  - xfs: use xfs_icluster_size_fsb in xfs_ialloc_inode_init
    (bsc#932805).

  - xfs: use xfs_icluster_size_fsb in xfs_ifree_cluster
    (bsc#932805).

  - xfs: use xfs_icluster_size_fsb in xfs_imap (bsc#932805).

  - xhci: Add spurious wakeup quirk for LynxPoint-LP
    controllers (bnc#949981).

  - xhci: Calculate old endpoints correctly on device reset
    (bnc#944831).

  - xhci: For streams the css flag most be read from the
    stream-ctx on ep stop (bnc#945691).

  - xhci: change xhci 1.0 only restrictions to support xhci
    1.1 (bnc#949502).

  - xhci: fix isoc endpoint dequeue from advancing too far
    on transaction error (bnc#944837).

  - xhci: silence TD warning (bnc#939955).

  - xhci: use uninterruptible sleep for waiting for internal
    operations (bnc#939955).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/814440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/879378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/879381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/900610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/941202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/946078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/946214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/946309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947957"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/948330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/948347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/948521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0272.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5157.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5307.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6937.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7509.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7799.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7872.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7990.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8104.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8215.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152339-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?baca640f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-kernel-source-12278=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-kernel-source-12278=1

SUSE Linux Enterprise Server 11-EXTRA :

zypper in -t patch slexsp3-kernel-source-12278=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-kernel-source-12278=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-kernel-source-12278=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"kernel-default-man-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-base-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-devel-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-source-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-syms-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-base-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-devel-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-base-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-base-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-devel-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-base-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-devel-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-default-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-default-base-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-default-devel-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-default-extra-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-source-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-syms-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-xen-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-pae-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kernel-pae-extra-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-default-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-default-base-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-default-devel-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-default-extra-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-source-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-syms-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-trace-devel-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-xen-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-xen-base-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-xen-devel-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-xen-extra-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-pae-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-pae-base-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-pae-devel-3.0.101-68.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kernel-pae-extra-3.0.101-68.1")) flag++;


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
