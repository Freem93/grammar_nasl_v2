#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-357.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74661);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2009-4020", "CVE-2011-3347", "CVE-2012-2119", "CVE-2012-2123", "CVE-2012-2136", "CVE-2012-2373", "CVE-2012-2663");
  script_osvdb_id(60795, 77571, 81812, 82038, 82459, 83105, 83194, 83205);

  script_name(english:"openSUSE Security Update : Kernel (openSUSE-SU-2012:0812-1)");
  script_summary(english:"Check for the openSUSE-2012-357 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update of the openSUSE 12.1 kernel brings various bug and
security fixes.

Following issues were fixed :

  - tcp: drop SYN+FIN messages (bnc#765102, CVE-2012-2663).

  - net: sock: validate data_len before allocating skb in
    sock_alloc_send_pskb() (bnc#765320, CVE-2012-2136).

  - thp: avoid atomic64_read in pmd_read_atomic for 32bit
    PAE (bnc#762991).

  - be2net: non-member vlan pkts not received in promiscous
    mode (bnc#732006 CVE-2011-3347).

  - fcaps: clear the same personality flags as suid when
    fcaps are used (bnc#758260 CVE-2012-2123).

  - macvtap: zerocopy: validate vectors before building skb
    (bnc#758243 CVE-2012-2119).

  - macvtap: zerocopy: set SKBTX_DEV_ZEROCOPY only when skb
    is built successfully (bnc#758243 CVE-2012-2119).

  - macvtap: zerocopy: put page when fail to get all
    requested user pages (bnc#758243 CVE-2012-2119).

  - macvtap: zerocopy: fix offset calculation when building
    skb (bnc#758243 CVE-2012-2119).

  - Avoid reading past buffer when calling GETACL
    (bnc#762992).

  - Avoid beyond bounds copy while caching ACL (bnc#762992).

  - Fix length of buffer copied in __nfs4_get_acl_uncached
    (bnc#762992).

  - hfsplus: Fix potential buffer overflows (bnc#760902
    CVE-2009-4020).

  - usb/net: rndis: merge command codes. only net/hyperv
    part

  - usb/net: rndis: remove ambiguous status codes. only
    net/hyperv part

  - usb/net: rndis: break out <linux/rndis.h> defines. only
    net/hyperv part

  - net/hyperv: Add flow control based on hi/low watermark.

  - hv: fix return type of hv_post_message().

  - Drivers: hv: util: Properly handle version negotiations.

  - Drivers: hv: Get rid of an unnecessary check in
    vmbus_prep_negotiate_resp().

  - HID: hyperv: Set the hid drvdata correctly.

  - HID: hid-hyperv: Do not use hid_parse_report() directly.

  - [SCSI] storvsc: Properly handle errors from the host
    (bnc#747404).

  - Delete patches.suse/suse-hv-storvsc-ignore-ata_16.patch.

  - patches.suse/suse-hv-pata_piix-ignore-disks.patch
    replace our version of this patch with upstream variant:
    ata_piix: defer disks to the Hyper-V drivers by default
    libata: add a host flag to ignore detected ATA devices.

  - mm: pmd_read_atomic: fix 32bit PAE pmd walk vs
    pmd_populate SMP race condition (bnc#762991
    CVE-2012-2373).

  - xfrm: take net hdr len into account for esp payload size
    calculation (bnc#759545).

  - net/hyperv: Adding cancellation to ensure rndis filter
    is closed.

  - xfs: Fix oops on IO error during
    xlog_recover_process_iunlinks() (bnc#761681).

  - thp: reduce khugepaged freezing latency (bnc#760860).

  - igb: fix rtnl race in PM resume path (bnc#748859).

  - ixgbe: add missing rtnl_lock in PM resume path
    (bnc#748859).

  - cdc_ether: Ignore bogus union descriptor for RNDIS
    devices (bnc#735362). Taking the fix from net-next

  - Fix kABI breakage due to including proc_fs.h in
    kernel/fork.c modversion changed because of changes in
    struct proc_dir_entry (became defined) Refresh
    patches.fixes/procfs-namespace-pid_ns-fix-leakage-on-for
    k-failure.

  - Disabled MMC_TEST (bnc#760077).

  - Input: ALPS - add semi-MT support for v3 protocol
    (bnc#716996).

  - Input: ALPS - add support for protocol versions 3 and 4
    (bnc#716996).

  - Input: ALPS - remove assumptions about packet size
    (bnc#716996).

  - Input: ALPS - add protocol version field in
    alps_model_info (bnc#716996).

  - Input: ALPS - move protocol information to Documentation
    (bnc#716996).

  - sysctl/defaults: kernel.hung_task_timeout ->
    kernel.hung_task_timeout_secs (bnc#700174)

  - btrfs: partial revert of truncation improvements
    (FATE#306586 bnc#748463 bnc#760279).

  - libata: skip old error history when counting probe
    trials.

  - procfs, namespace, pid_ns: fix leakage upon fork()
    failure (bnc#757783).

  - cdc-wdm: fix race leading leading to memory corruption
    (bnc#759554). This patch fixes a race whereby a pointer
    to a buffer would be overwritten while the buffer was in
    use leading to a double free and a memory leak. This
    causes crashes. This bug was introduced in 2.6.34

  - netfront: delay gARP until backend switches to
    Connected.

  - xenbus: Reject replies with payload >
    XENSTORE_PAYLOAD_MAX.

  - xenbus: check availability of XS_RESET_WATCHES command.

  - xenbus_dev: add missing error checks to watch handling.

  - drivers/xen/: use strlcpy() instead of strncpy().

  - blkfront: properly fail packet requests (bnc#745929).

  - Linux 3.1.10.

  - Update Xen config files.

  - Refresh other Xen patches.

  - tlan: add cast needed for proper 64 bit operation
    (bnc#756840).

  - dl2k: Tighten ioctl permissions (bnc#758813).

  - mqueue: fix a vfsmount longterm reference leak
    (bnc#757783).

  - cciss: Add IRQF_SHARED back in for the non-MSI(X)
    interrupt handler (bnc#757789).

  - procfs: fix a vfsmount longterm reference leak
    (bnc#757783).

  - uwb: fix error handling (bnc#731720). This fixes a
    kernel error on unplugging an uwb dongle

  - uwb: fix use of del_timer_sync() in interrupt
    (bnc#731720). This fixes a kernel warning on plugging in
    an uwb dongle

  - acer-wmi: Detect communication hot key number.

  - acer-wmi: replaced the hard coded bitmap by the
    communication devices bitmap from SMBIOS.

  - acer-wmi: add ACER_WMID_v2 interface flag to represent
    new notebooks.

  - acer-wmi: No wifi rfkill on Sony machines.

  - acer-wmi: No wifi rfkill on Lenovo machines.

  - [media] cx22702: Fix signal strength.

  - fs: cachefiles: Add support for large files in
    filesystem caching (bnc#747038).

  - Drivers: scsi: storvsc: Account for in-transit packets
    in the RESET path.

  - CPU hotplug, cpusets, suspend: Don't touch cpusets
    during suspend/resume (bnc#752460).

  - net: fix a potential rcu_read_lock() imbalance in
    rt6_fill_node() (bnc#754186, bnc#736268).

  - This commit fixes suspend to ram breakage reported in
    bnc#764864. Remove dud patch. The problem it addressed
    is being respun upstream, is in tip, but not yet
    mainlined. See bnc#752460 for details regarding the
    problem the now removed patch fixed while breaking S2R.
    Delete
    patches.fixes/cpusets-Dont-touch-cpusets-during-suspend-
    or-resume.patch.

  - Remove dud patch. The problem it addressed is being
    respun upstream, is in tip, but not yet mainlined.
    Delete
    patches.fixes/cpusets-Dont-touch-cpusets-during-suspend-
    or-resume.patch.

  - fix VM_FOREIGN users after c/s 878:eba6fe6d8d53
    (bnc#760974).

  - gntdev: fix multi-page slot allocation (bnc#760974).

  - mm: pmd_read_atomic: fix 32bit PAE pmd walk vs
    pmd_populateSMP race condition (bnc#762991
    CVE-2012-2373).

  - thp: avoid atomic64_read in pmd_read_atomic for 32bit
    PAE (bnc#762991).

  - sym53c8xx: Fix NULL pointer dereference in slave_destroy
    (bnc#767786).

  - sky2: fix regression on Yukon Optima (bnc#731537)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-07/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=700174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=716996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=731537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=731720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=735362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=736268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=752460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=756840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=761681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=764864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=767786"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-base-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-base-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-debugsource-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-devel-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-devel-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-base-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-base-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-debugsource-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-devel-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-devel-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-base-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-base-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-debugsource-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-devel-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-devel-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-devel-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-base-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-base-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-debugsource-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-devel-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-devel-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-extra-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-extra-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-base-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-base-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-debugsource-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-devel-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-devel-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-source-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-source-vanilla-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-syms-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-base-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-base-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-debugsource-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-devel-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-devel-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-base-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-base-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-debugsource-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-devel-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-devel-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-base-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-base-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-debuginfo-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-debugsource-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-devel-3.1.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-devel-debuginfo-3.1.10-1.16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-base-debuginfo / etc");
}
