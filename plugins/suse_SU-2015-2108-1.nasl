#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2108-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87104);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2015-0272", "CVE-2015-5157", "CVE-2015-5307", "CVE-2015-6252", "CVE-2015-6937", "CVE-2015-7872", "CVE-2015-7990", "CVE-2015-8104");
  script_bugtraq_id(76005);
  script_osvdb_id(125208, 126403, 127518, 127759, 129330, 130089, 130090);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : kernel (SUSE-SU-2015:2108-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 3 kernel was updated to
receive various security and bugfixes.

Following security bugs were fixed :

  - CVE-2015-8104: Prevent guest to host DoS caused by
    infinite loop in microcode via #DB exception
    (bsc#954404).

  - CVE-2015-5307: Prevent guest to host DoS caused by
    infinite loop in microcode via #AC exception
    (bsc#953527).

  - CVE-2015-7990: RDS: Verify the underlying transport
    exists before creating a connection, preventing possible
    DoS (bsc#952384).

  - CVE-2015-5157: arch/x86/entry/entry_64.S in the Linux
    kernel on the x86_64 platform mishandled IRET faults in
    processing NMIs that occurred during userspace
    execution, which might have allowed local users to gain
    privileges by triggering an NMI (bsc#938706).

  - CVE-2015-7872: Possible crash when trying to garbage
    collect an uninstantiated keyring (bsc#951440).

  - CVE-2015-0272: Prevent remote DoS using IPv6 RA with
    bogus MTU by validating before applying it (bsc#944296).

  - CVE-2015-6937: The __rds_conn_create function in
    net/rds/connection.c in the Linux kernel allowed local
    users to cause a denial of service (NULL pointer
    dereference and system crash) or possibly have
    unspecified other impact by using a socket that was not
    properly bound (bsc#945825).

  - CVE-2015-6252: The vhost_dev_ioctl function in
    drivers/vhost/vhost.c in the Linux kernel allowed local
    users to cause a denial of service (memory consumption)
    via a VHOST_SET_LOG_FD ioctl call that triggered
    permanent file-descriptor allocation (bsc#942367).

The following non-security bugs were fixed :

  - alsa: hda - Disable 64bit address for Creative HDA
    controllers (bsc#814440).

  - btrfs: fix hang when failing to submit bio of directIO
    (bsc#942688).

  - btrfs: fix memory corruption on failure to submit bio
    for direct IO (bsc#942688).

  - btrfs: fix put dio bio twice when we submit dio bio fail
    (bsc#942688).

  - dm sysfs: introduce ability to add writable attributes
    (bsc#904348).

  - dm-snap: avoid deadock on s->lock when a read is split
    (bsc#939826).

  - dm: do not start current request if it would have merged
    with the previous (bsc#904348).

  - dm: impose configurable deadline for dm_request_fn merge
    heuristic (bsc#904348).

  - drm/i915: (re)init HPD interrupt storm statistics
    (bsc#942938).

  - drm/i915: Add HPD IRQ storm detection (v5) (bsc#942938).

  - drm/i915: Add Reenable Timer to turn Hotplug Detection
    back on (v4) (bsc#942938).

  - drm/i915: Add bit field to record which pins have
    received HPD events (v3) (bsc#942938).

  - drm/i915: Add enum hpd_pin to intel_encoder
    (bsc#942938).

  - drm/i915: Add messages useful for HPD storm detection
    debugging (v2) (bsc#942938).

  - drm/i915: Avoid race of intel_crt_detect_hotplug() with
    HPD interrupt (bsc#942938).

  - drm/i915: Convert HPD interrupts to make use of HPD pin
    assignment in encoders (v2) (bsc#942938).

  - drm/i915: Disable HPD interrupt on pin when irq storm is
    detected (v3) (bsc#942938).

  - drm/i915: Do not WARN nor handle unexpected hpd
    interrupts on gmch platforms (bsc#942938).

  - drm/i915: Enable hotplug interrupts after querying hw
    capabilities (bsc#942938).

  - drm/i915: Fix DDC probe for passive adapters
    (bsc#900610, fdo#85924).

  - drm/i915: Fix hotplug interrupt enabling for SDVOC
    (bsc#942938).

  - drm/i915: Fix up sdvo hpd pins for i965g/gm
    (bsc#942938).

  - drm/i915: Get rid if the '^A' in struct drm_i915_private
    (bsc#942938).

  - drm/i915: Make hpd arrays big enough to avoid out of
    bounds access (bsc#942938).

  - drm/i915: Mask out the HPD irq bits before setting them
    individually (bsc#942938).

  - drm/i915: Only print hotplug event message when hotplug
    bit is set (bsc#942938).

  - drm/i915: Only reprobe display on encoder which has
    received an HPD event (v2) (bsc#942938).

  - drm/i915: Queue reenable timer also when
    enable_hotplug_processing is false (bsc#942938).

  - drm/i915: Remove i965_hpd_irq_setup (bsc#942938).

  - drm/i915: Remove pch_rq_mask from struct
    drm_i915_private (bsc#942938).

  - drm/i915: Remove valleyview_hpd_irq_setup (bsc#942938).

  - drm/i915: Use an interrupt save spinlock in
    intel_hpd_irq_handler() (bsc#942938).

  - drm/i915: WARN_ONCE() about unexpected interrupts for
    all chipsets (bsc#942938).

  - drm/i915: add hotplug activation period to hotplug
    update mask (bsc#953980).

  - drm/i915: assert_spin_locked for pipestat interrupt
    enable/disable (bsc#942938).

  - drm/i915: clear crt hotplug compare voltage field before
    setting (bsc#942938).

  - drm/i915: close tiny race in the ilk pcu even interrupt
    setup (bsc#942938).

  - drm/i915: fix hotplug event bit tracking (bsc#942938).

  - drm/i915: fix hpd interrupt register locking
    (bsc#942938).

  - drm/i915: fix hpd work vs. flush_work in the pageflip
    code deadlock (bsc#942938).

  - drm/i915: fix locking around
    ironlake_enable|disable_display_irq (bsc#942938).

  - drm/i915: fold the hpd_irq_setup call into
    intel_hpd_irq_handler (bsc#942938).

  - drm/i915: fold the no-irq check into
    intel_hpd_irq_handler (bsc#942938).

  - drm/i915: fold the queue_work into intel_hpd_irq_handler
    (bsc#942938).

  - drm/i915: implement ibx_hpd_irq_setup (bsc#942938).

  - drm/i915:
    s/hotplug_irq_storm_detect/intel_hpd_irq_handler/
    (bsc#942938).

  - ehci-pci: enable interrupt on BayTrail (bnc926007).

  - fix lpfc_send_rscn_event allocation size claims
    bsc#935757

  - hugetlb: simplify migrate_huge_page() (bsc#947957, VM
    Functionality).

  - hwpoison, hugetlb: lock_page/unlock_page does not match
    for handling a free hugepage (bsc#947957).

  - ib/iser: Add Discovery support (bsc#923002).

  - ib/iser: Move informational messages from error to info
    level (bsc#923002).

  - ib/srp: Avoid skipping srp_reset_host() after a
    transport error (bsc#904965).

  - ib/srp: Fix a sporadic crash triggered by cable pulling
    (bsc#904965).

  - inotify: Fix nested sleeps in inotify_read()
    (bsc#940925).

  - ipv6: fix tunnel error handling (bsc#952579).

  - ipv6: probe routes asynchronous in rt6_probe
    (bsc#936118).

  - ipvs: Fix reuse connection if real server is dead
    (bsc#945827).

  - ipvs: drop first packet to dead server (bsc#946078).

  - keys: Fix race between key destruction and finding a
    keyring by name (bsc#951440).

  - ktime: add ktime_after and ktime_before helpe
    (bsc#904348).

  - lib/string.c: introduce memchr_inv() (bsc#930788).

  - libiscsi: Exporting new attrs for iscsi session and
    connection in sysfs (bsc#923002).

  - macvlan: Support bonding events bsc#948521

  - make sure XPRT_CONNECTING gets cleared when needed
    (bsc#946309).

  - memory-failure: do code refactor of soft_offline_page()
    (bsc#947957).

  - memory-failure: fix an error of mce_bad_pages statistics
    (bsc#947957).

  - memory-failure: use num_poisoned_pages instead of
    mce_bad_pages (bsc#947957).

  - memory-hotplug: update mce_bad_pages when removing the
    memory (bsc#947957).

  - mm/memory-failure.c: fix wrong num_poisoned_pages in
    handling memory error on thp (bsc#947957).

  - mm/memory-failure.c: recheck PageHuge() after hugetlb
    page migrate successfully (bsc#947957).

  - mm/migrate.c: pair unlock_page() and lock_page() when
    migrating huge pages (bsc#947957).

  - mm: exclude reserved pages from dirtyable memory 32b fix
    (bsc#940017, bsc#949298).

  - mm: make page pfmemalloc check more robust (bsc#920016).

  - netfilter: nf_conntrack_proto_sctp: minimal multihoming
    support (bsc#932350).

  - pci: Add VPD function 0 quirk for Intel Ethernet devices
    (bsc#943786).

  - pci: Add dev_flags bit to access VPD through function 0
    (bsc#943786).

  - pci: Add flag indicating device has been assigned by KVM
    (bsc#777565).

  - pci: Clear NumVFs when disabling SR-IOV in sriov_init()
    (bsc#952084).

  - pci: Refresh First VF Offset and VF Stride when updating
    NumVFs (bsc#952084).

  - pci: Update NumVFs register when disabling SR-IOV
    (bsc#952084).

  - pci: delay configuration of SRIOV capability
    (bsc#952084).

  - pci: set pci sriov page size before reading SRIOV BAR
    (bsc#952084).

  - pktgen: clean up ktime_t helpers (bsc#904348).

  - qla2xxx: Do not reset adapter if SRB handle is in range
    (bsc#944993).

  - qla2xxx: Remove decrement of sp reference count in abort
    handler (bsc#944993).

  - qla2xxx: do not clear slot in outstanding cmd array
    (bsc#944993).

  - r8169: remember WOL preferences on driver load
    (bsc#942305).

  - rcu: Eliminate deadlock between CPU hotplug and
    expedited grace periods (bsc#949706).

  - rtc: cmos: Cancel alarm timer if alarm time is equal to
    now+1 seconds (bsc#930145).

  - sched/core: Fix task and run queue sched_info::run_delay
    inconsistencies (bsc#949100).

  - scsi: fix scsi_error_handler vs. scsi_host_dev_release
    race (bsc#942204).

  - scsi: hosts: update to use ida_simple for host_no
    (bsc#939926)

  - scsi: kabi: allow iscsi disocvery session support
    (bsc#923002).

  - scsi_transport_iscsi: Exporting new attrs for iscsi
    session and connection in sysfs (bsc#923002).

  - sg: fix read() error reporting (bsc#926774).

  - usb: xhci: Prefer endpoint context dequeue pointer over
    stopped_trb (bsc#933721).

  - usb: xhci: Reset a halted endpoint immediately when we
    encounter a stall (bsc#933721).

  - usb: xhci: apply XHCI_AVOID_BEI quirk to all Intel xHCI
    controllers (bsc#944989).

  - usb: xhci: do not start a halted endpoint before its new
    dequeue is set (bsc#933721).

  - usb: xhci: handle Config Error Change (CEC) in xhci
    driver (bsc#933721).

  - x86/tsc: Change Fast TSC calibration failed from error
    to info (bsc#942605).

  - x86: mm: drop TLB flush from ptep_set_access_flags
    (bsc#948330).

  - x86: mm: only do a local tlb flush in
    ptep_set_access_flags() (bsc#948330).

  - xfs: Fix lost direct IO write in the last block
    (bsc#949744).

  - xfs: Fix softlockup in xfs_inode_ag_walk() (bsc#948347).

  - xfs: add EOFBLOCKS inode tagging/untagging (bsc#930788).

  - xfs: add XFS_IOC_FREE_EOFBLOCKS ioctl (bsc#930788).

  - xfs: add background scanning to clear eofblocks inodes
    (bsc#930788).

  - xfs: add inode id filtering to eofblocks scan
    (bsc#930788).

  - xfs: add minimum file size filtering to eofblocks scan
    (bsc#930788).

  - xfs: create function to scan and clear EOFBLOCKS inodes
    (bsc#930788).

  - xfs: create helper to check whether to free eofblocks on
    inode (bsc#930788).

  - xfs: introduce a common helper xfs_icluster_size_fsb
    (bsc#932805).

  - xfs: make xfs_free_eofblocks() non-static, return EAGAIN
    on trylock failure (bsc#930788).

  - xfs: support a tag-based inode_ag_iterator (bsc#930788).

  - xfs: support multiple inode id filtering in eofblocks
    scan (bsc#930788).

  - xfs: use xfs_icluster_size_fsb in xfs_bulkstat
    (bsc#932805).

  - xfs: use xfs_icluster_size_fsb in xfs_ialloc_inode_init
    (bsc#932805).

  - xfs: use xfs_icluster_size_fsb in xfs_ifree_cluster
    (bsc#932805).

  - xfs: use xfs_icluster_size_fsb in xfs_imap (bsc#932805).

  - xhci: Add spurious wakeup quirk for LynxPoint-LP
    controllers (bsc#949981).

  - xhci: Allocate correct amount of scratchpad buffers
    (bsc#933721).

  - xhci: Calculate old endpoints correctly on device reset
    (bsc#944831).

  - xhci: Do not enable/disable RWE on bus suspend/resume
    (bsc#933721).

  - xhci: For streams the css flag most be read from the
    stream-ctx on ep stop (bsc#945691).

  - xhci: Solve full event ring by increasing
    TRBS_PER_SEGMENT to 256 (bsc#933721).

  - xhci: Treat not finding the event_seg on COMP_STOP the
    same as COMP_STOP_INVAL (bsc#933721).

  - xhci: Workaround for PME stuck issues in Intel xhci
    (bsc#933721).

  - xhci: change xhci 1.0 only restrictions to support xhci
    1.1 (bsc#949502).

  - xhci: do not report PLC when link is in internal resume
    state (bsc#933721).

  - xhci: fix isoc endpoint dequeue from advancing too far
    on transaction error (bsc#944837).

  - xhci: fix reporting of 0-sized URBs in control endpoint
    (bsc#933721).

  - xhci: report U3 when link is in resume state
    (bsc#933721).

  - xhci: rework cycle bit checking for new dequeue pointers
    (bsc#933721).

  - xhci: use uninterruptible sleep for waiting for internal
    operations (bsc#939955).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/777565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/814440"
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
    value:"https://bugzilla.suse.com/920016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/923002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926709"
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
    value:"https://bugzilla.suse.com/930788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936118"
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
    value:"https://bugzilla.suse.com/940925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/941202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942688"
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
    value:"https://bugzilla.suse.com/949981"
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
    value:"https://bugzilla.suse.com/953527"
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
    value:"https://www.suse.com/security/cve/CVE-2015-6252.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6937.html"
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
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152108-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?911cfa21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP3 :

zypper in -t patch sdksp3-kernel-source-12226=1

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-kernel-source-12226=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-kernel-source-12226=1

SUSE Linux Enterprise Server 11-EXTRA :

zypper in -t patch slexsp3-kernel-source-12226=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-kernel-source-12226=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-kernel-source-12226=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-extra");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/30");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-base-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-extra-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-trace-extra-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-extra-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-base-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-source-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-syms-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-base-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-extra-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-extra-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-extra-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-base-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-extra-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-source-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-syms-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-extra-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-base-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-extra-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-source-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-syms-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-trace-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-extra-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.71.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-extra-3.0.101-0.47.71.1")) flag++;


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
