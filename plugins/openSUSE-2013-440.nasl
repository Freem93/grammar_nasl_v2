#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-440.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75012);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/09 14:34:06 $");

  script_cve_id("CVE-2013-0913", "CVE-2013-1763", "CVE-2013-1767", "CVE-2013-1774", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798", "CVE-2013-1848");
  script_osvdb_id(90604, 90665, 90678, 91254, 91561, 91562, 91563, 91567);

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2013:0824-1)");
  script_summary(english:"Check for the openSUSE-2013-440 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Linux kernel was updated to kernel 3.4.42 fixing various bugs and
security issues.

  - Refresh patches.suse/SUSE-bootsplash. Fix bootsplash
    breakage due to stable fix (bnc#813963)

  - Linux 3.4.39.

  - kABI: protect struct tracer.

  - Linux 3.4.38 (bnc#808829,CVE-2013-0913).

  - patches.kabi/kabi-protect-struct-sk_buff.patch: kABI:
    protect struct sk_buff.

  - patches.kabi/kabi-ipv4-remove-inclusion.patch: kABI:
    ipv4, remove inclusion.

  - USB: io_ti: Fix NULL dereference in chase_port()
    (bnc#806976, CVE-2013-1774).

  - Linux 3.4.37 (bnc#809155 bnc#809330 bnc#809748
    CVE-2013-1848).

  - Linux 3.4.36.

  - KVM: Convert MSR_KVM_SYSTEM_TIME to use
    gfn_to_hva_cache_init (bnc#806980 CVE-2013-1797).

  - KVM: Fix bounds checking in ioapic indirect register
    read (bnc#806980 CVE-2013-1798).

  - KVM: Fix for buffer overflow in handling of
    MSR_KVM_SYSTEM_TIME (bnc#806980 CVE-2013-1796).

  - kabi/severities: Allow kvm abi changes - kvm modules are
    self consistent

  - loopdev: fix a deadlock (bnc#809748).

  - block: use i_size_write() in bd_set_size() (bnc#809748).

  - drm/i915: bounds check execbuffer relocation count
    (bnc#808829,CVE-2013-0913).

  - TTY: do not reset master's packet mode (bnc#809330).

  - Update patches.fixes/ext3-Fix-format-string-issues.patch
    (bnc#809155 CVE-2013-1848).

  - ext3: Fix format string issues (bnc#809155).

  - Linux 3.4.35 (bnc#802153).

  - Linux 3.4.34 (CVE-2013-1763 CVE-2013-1767 bnc#792500
    bnc#806138 bnc#805633).

  - tmpfs: fix use-after-free of mempolicy object
    (bnc#806138, CVE-2013-1767)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-05/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=805633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813963"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-base-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-base-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-debugsource-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-devel-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-devel-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-devel-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-source-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-source-vanilla-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-syms-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-base-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-debugsource-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-devel-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-base-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-debugsource-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-devel-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-devel-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-base-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-debugsource-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-devel-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-devel-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-extra-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-extra-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-base-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-debugsource-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-devel-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-devel-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-base-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-base-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-debugsource-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-devel-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-devel-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-vanilla-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-vanilla-debugsource-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-vanilla-devel-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-vanilla-devel-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-base-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-debugsource-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-devel-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-devel-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-base-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-debugsource-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-devel-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-base-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-devel-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-devel-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-base-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-devel-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-devel-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-extra-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-extra-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-base-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-debugsource-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-devel-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-devel-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-base-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-base-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-debugsource-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-devel-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-devel-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-vanilla-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-vanilla-devel-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-vanilla-devel-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-base-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-debugsource-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-devel-3.4.42-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-devel-debuginfo-3.4.42-2.28.1") ) flag++;

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
