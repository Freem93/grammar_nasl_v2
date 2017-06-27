#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-3396.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75552);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2010-2963", "CVE-2010-3904");

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2010:0902-1)");
  script_summary(english:"Check for the kernel-3396 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of the openSUSE 11.3 Linux kernel fixes two critical
security issues and some bugs.

Following security issues were fixed: CVE-2010-3904: A local privilege
escalation in RDS sockets allowed local attackers to gain privileges.

CVE-2010-2963: A problem in the compat ioctl handling in video4linux
allowed local attackers with a video device plugged in to gain
privileges on x86_64 systems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-10/msg00033.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=564324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=573330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=643477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=645066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=646045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=647392"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-base-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-devel-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-base-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-devel-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-base-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-devel-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-devel-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-base-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-devel-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-extra-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-base-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-devel-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-source-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-source-vanilla-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-syms-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-base-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-devel-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-base-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-devel-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vmi-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vmi-base-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vmi-devel-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-base-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-devel-2.6.34.7-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"preload-kmp-default-1.1_k2.6.34.7_0.5-19.1.8") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"preload-kmp-desktop-1.1_k2.6.34.7_0.5-19.1.8") ) flag++;

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
