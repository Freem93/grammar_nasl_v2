#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2194-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87214);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2015-0272", "CVE-2015-2925", "CVE-2015-5283", "CVE-2015-5307", "CVE-2015-7799", "CVE-2015-7872", "CVE-2015-7990", "CVE-2015-8104", "CVE-2015-8215");
  script_bugtraq_id(73926);
  script_osvdb_id(120327, 127518, 127759, 128012, 128845, 129330, 130089, 130090);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2015:2194-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 kernel was updated to 3.12.51 to receive
various security and bugfixes.

Following security bugs were fixed :

  - CVE-2015-7799: The slhc_init function in
    drivers/net/slip/slhc.c in the Linux kernel did not
    ensure that certain slot numbers were valid, which
    allowed local users to cause a denial of service (NULL
    pointer dereference and system crash) via a crafted
    PPPIOCSMAXCID ioctl call (bnc#949936).

  - CVE-2015-5283: The sctp_init function in
    net/sctp/protocol.c in the Linux kernel had an incorrect
    sequence of protocol-initialization steps, which allowed
    local users to cause a denial of service (panic or
    memory corruption) by creating SCTP sockets before all
    of the steps have finished (bnc#947155).

  - CVE-2015-2925: The prepend_path function in fs/dcache.c
    in the Linux kernel did not properly handle rename
    actions inside a bind mount, which allowed local users
    to bypass an intended container protection mechanism by
    renaming a directory, related to a 'double-chroot attack
    (bnc#926238).

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

  - CVE-2015-7872: The key_gc_unused_keys function in
    security/keys/gc.c in the Linux kernel allowed local
    users to cause a denial of service (OOPS) via crafted
    keyctl commands (bnc#951440).

  - CVE-2015-0272: Missing checks allowed remote attackers
    to cause a denial of service (IPv6 traffic disruption)
    via a crafted MTU value in an IPv6 Router Advertisement
    (RA) message, a different vulnerability than
    CVE-2015-8215 (bnc#944296).

The following non-security bugs were fixed :

  - ALSA: hda - Disable 64bit address for Creative HDA
    controllers (bnc#814440).

  - Add PCI IDs of Intel Sunrise Point-H SATA Controller
    S232/236 (bsc#953796).

  - Btrfs: fix file corruption and data loss after cloning
    inline extents (bnc#956053).

  - Btrfs: fix truncation of compressed and inlined extents
    (bnc#956053).

  - Disable some ppc64le netfilter modules to restore the
    kabi (bsc#951546)

  - Fix regression in NFSRDMA server (bsc#951110).

  - KEYS: Fix race between key destruction and finding a
    keyring by name (bsc#951440).

  - KVM: x86: call irq notifiers with directed EOI
    (bsc#950862).

  - NVMe: Add shutdown timeout as module parameter
    (bnc#936076).

  - NVMe: Mismatched host/device page size support
    (bsc#935961).

  - PCI: Drop 'setting latency timer' messages (bsc#956047).

  - SCSI: Fix hard lockup in scsi_remove_target()
    (bsc#944749).

  - SCSI: hosts: update to use ida_simple for host_no
    (bsc#939926)

  - SUNRPC: Fix oops when trace sunrpc_task events in nfs
    client (bnc#956703).

  - Sync ppc64le netfilter config options with other archs
    (bnc#951546)

  - Update kabi files with sbc_parse_cdb symbol change
    (bsc#954635).

  - apparmor: allow SYS_CAP_RESOURCE to be sufficient to
    prlimit another task (bsc#921949).

  - apparmor: temporary work around for bug while unloading
    policy (boo#941867).

  - audit: correctly record file names with different path
    name types (bsc#950013).

  - audit: create private file name copies when auditing
    inodes (bsc#950013).

  - cpu: Defer smpboot kthread unparking until CPU known to
    scheduler (bsc#936773).

  - dlm: make posix locks interruptible, (bsc#947241).

  - dm sysfs: introduce ability to add writable attributes
    (bsc#904348).

  - dm-snap: avoid deadock on s->lock when a read is split
    (bsc#939826).

  - dm: do not start current request if it would've merged
    with the previous (bsc#904348).

  - dm: impose configurable deadline for dm_request_fn's
    merge heuristic (bsc#904348).

  - dmapi: Fix xfs dmapi to not unlock and lock
    XFS_ILOCK_EXCL (bsc#949744).

  - drm/i915: Avoid race of intel_crt_detect_hotplug() with
    HPD interrupt, v2 (bsc#942938).

  - drm/i915: add hotplug activation period to hotplug
    update mask (bsc#953980).

  - fanotify: fix notification of groups with inode and
    mount marks (bsc#955533).

  - genirq: Make sure irq descriptors really exist when
    __irq_alloc_descs returns (bsc#945626).

  - hv: vss: run only on supported host versions
    (bnc#949504).

  - ipv4: Do not increase PMTU with Datagram Too Big message
    (bsc#955224).

  - ipv6: Check RTF_LOCAL on rt->rt6i_flags instead of
    rt->dst.flags (bsc#947321).

  - ipv6: Consider RTF_CACHE when searching the fib6 tree
    (bsc#947321).

  - ipv6: Extend the route lookups to low priority metrics
    (bsc#947321).

  - ipv6: Stop /128 route from disappearing after pmtu
    update (bsc#947321).

  - ipv6: Stop rt6_info from using inet_peer's metrics
    (bsc#947321).

  - ipv6: distinguish frag queues by device for multicast
    and link-local packets (bsc#955422).

  - ipvs: drop first packet to dead server (bsc#946078).

  - kABI: protect struct ahci_host_priv.

  - kABI: protect struct rt6_info changes from bsc#947321
    changes (bsc#947321).

  - kabi: Hide rt6_* types from genksyms on ppc64le
    (bsc#951546).

  - kabi: Restore kabi in struct iscsi_tpg_attrib
    (bsc#954635).

  - kabi: Restore kabi in struct se_cmd (bsc#954635).

  - kabi: Restore kabi in struct se_subsystem_api
    (bsc#954635).

  - kabi: protect skb_copy_and_csum_datagram_iovec()
    signature (bsc#951199).

  - kgr: fix migration of kthreads to the new universe.

  - kgr: wake up kthreads periodically.

  - ktime: add ktime_after and ktime_before helper
    (bsc#904348).

  - macvlan: Support bonding events (bsc#948521).

  - net: add length argument to
    skb_copy_and_csum_datagram_iovec (bsc#951199).

  - net: handle null iovec pointer in
    skb_copy_and_csum_datagram_iovec() (bsc#951199).

  - pci: Update VPD size with correct length (bsc#924493).

  - rcu: Eliminate deadlock between CPU hotplug and
    expedited grace periods (bsc#949706).

  - ring-buffer: Always run per-cpu ring buffer resize with
    schedule_work_on() (bnc#956711).

  - route: Use ipv4_mtu instead of raw rt_pmtu (bsc#955224).

  - rtc: cmos: Cancel alarm timer if alarm time is equal to
    now+1 seconds (bsc#930145).

  - rtc: cmos: Revert 'rtc-cmos: Add an alarm disable quirk'
    (bsc#930145).

  - sched/core: Fix task and run queue sched_info::run_delay
    inconsistencies (bnc#949100).

  - sunrpc/cache: make cache flushing more reliable
    (bsc#947478).

  - supported.conf: Add missing dependencies of supported
    modules hwmon_vid needed by nct6775 hwmon_vid needed by
    w83627ehf reed_solomon needed by ramoops

  - supported.conf: Fix dependencies on ppc64le of_mdio
    needed by mdio-gpio

  - target/pr: fix core_scsi3_pr_seq_non_holder() caller
    (bnc#952666).

  - target/rbd: fix COMPARE AND WRITE page vector leak
    (bnc#948831).

  - target/rbd: fix PR info memory leaks (bnc#948831).

  - target: Send UA upon LUN RESET tmr completion
    (bsc#933514).

  - target: use '^A' when allocating UAs (bsc#933514).

  - usbvision fix overflow of interfaces array (bnc#950998).

  - vmxnet3: Fix ethtool -S to return correct rx queue stats
    (bsc#950750).

  - vmxnet3: adjust ring sizes when interface is down
    (bsc#950750).

  - x86/efi: Fix boot crash by mapping EFI memmap entries
    bottom-up at runtime, instead of top-down (bsc#940853).

  - x86/evtchn: make use of PHYSDEVOP_map_pirq.

  - x86/mm/hotplug: Modify PGD entry when removing memory
    (VM Functionality, bnc#955148).

  - x86/mm/hotplug: Pass sync_global_pgds() a correct
    argument in remove_pagetable() (VM Functionality,
    bnc#955148).

  - xfs: DIO needs an ioend for writes (bsc#949744).

  - xfs: DIO write completion size updates race
    (bsc#949744).

  - xfs: DIO writes within EOF do not need an ioend
    (bsc#949744).

  - xfs: always drain dio before extending aio write
    submission (bsc#949744).

  - xfs: direct IO EOF zeroing needs to drain AIO
    (bsc#949744).

  - xfs: do not allocate an ioend for direct I/O completions
    (bsc#949744).

  - xfs: factor DIO write mapping from get_blocks
    (bsc#949744).

  - xfs: handle DIO overwrite EOF update completion
    correctly (bsc#949744).

  - xfs: move DIO mapping size calculation (bsc#949744).

  - xfs: using generic_file_direct_write() is unnecessary
    (bsc#949744).

  - xhci: Add spurious wakeup quirk for LynxPoint-LP
    controllers (bnc#951165).

  - xhci: change xhci 1.0 only restrictions to support xhci
    1.1 (bnc#949463).

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
    value:"https://bugzilla.suse.com/867595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936773"
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
    value:"https://bugzilla.suse.com/940853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/941202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/941867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/946078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/948521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/948685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/948831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949504"
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
    value:"https://bugzilla.suse.com/950013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0272.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2925.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5283.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5307.html"
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
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152194-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e36375c5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2015-945=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-945=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-945=1

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2015-945=1

SUSE Linux Enterprise Live Patching 12 :

zypper in -t patch SUSE-SLE-Live-Patching-12-2015-945=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-945=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/07");
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
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"kernel-default-man-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-debuginfo-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debuginfo-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debugsource-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-devel-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-syms-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-devel-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-syms-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.51-52.31.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.51-52.31.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
