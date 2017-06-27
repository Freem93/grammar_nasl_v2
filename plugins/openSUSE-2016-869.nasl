#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-869.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(92308);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2016-4470", "CVE-2016-4794", "CVE-2016-4997", "CVE-2016-5829");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2016-869)");
  script_summary(english:"Check for the openSUSE-2016-869 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.1 was updated to 4.1.27 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2016-4997: A buffer overflow in 32bit
    compat_setsockopt iptables handling could lead to a
    local privilege escalation. (bsc#986362)

  - CVE-2016-5829: Multiple heap-based buffer overflows in
    the hiddev_ioctl_usage function in
    drivers/hid/usbhid/hiddev.c in the Linux kernel allow
    local users to cause a denial of service or possibly
    have unspecified other impact via a crafted (1)
    HIDIOCGUSAGES or (2) HIDIOCSUSAGES ioctl call
    (bnc#986572).

  - CVE-2016-4470: The key_reject_and_link function in
    security/keys/key.c in the Linux kernel did not ensure
    that a certain data structure is initialized, which
    allowed local users to cause a denial of service (system
    crash) via vectors involving a crafted keyctl request2
    command (bnc#984755).

  - CVE-2016-4794: Use-after-free vulnerability in
    mm/percpu.c in the Linux kernel allowed local users to
    cause a denial of service (BUG) or possibly have
    unspecified other impact via crafted use of the mmap and
    bpf system calls (bnc#980265).

The following non-security bugs were fixed :

  - Refresh patches.xen/xen-netback-coalesce: Restore
    copying of SKBs with head exceeding page size
    (bsc#978469).

  - Refresh patches.xen/xen3-patch-2.6.26 (fix PAT
    initialization).

  - Refresh patches.xen/xen3-patch-2.6.39 (fix ia32_compat
    inheritance).

  - Refresh patches.xen/xen3-patch-3.14: Suppress atomic
    file position updates for /proc/xen/xenbus (bsc#970275).

  - Refresh patches.xen/xen3-patch-3.16 (drop redundant
    addition of a comment).

  - Refresh patches.xen/xen3-patch-4.1.7-8.

  - base: make module_create_drivers_dir race-free
    (bnc#983977).

  - ipvs: count pre-established TCP states as active
    (bsc#970114).

  - net: thunderx: Fix TL4 configuration for secondary Qsets
    (bsc#986530).

  - net: thunderx: Fix link status reporting (bsc#986530)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986572"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/15");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-base-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-base-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-debugsource-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-devel-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-devel-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-docs-html-4.1.27-24.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-docs-pdf-4.1.27-24.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-macros-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-build-4.1.27-24.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-build-debugsource-4.1.27-24.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-qa-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-qa-xen-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-source-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-source-vanilla-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-syms-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-base-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-base-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-debugsource-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-devel-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-devel-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-base-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-base-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-debugsource-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-devel-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-base-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-base-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-debugsource-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-devel-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-base-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-base-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-debugsource-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-devel-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-debugsource-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-devel-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-base-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-base-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-debugsource-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-devel-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-base-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-debugsource-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-devel-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-base-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-debugsource-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-devel-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-base-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-debugsource-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-devel-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-base-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-base-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-debugsource-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-devel-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-debugsource-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-devel-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-base-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-debuginfo-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-debugsource-4.1.27-24.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-devel-4.1.27-24.1") ) flag++;

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
