#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-680.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86667);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/11/20 15:06:53 $");

  script_cve_id("CVE-2015-7384");

  script_name(english:"openSUSE Security Update : nodejs (openSUSE-2015-680)");
  script_summary(english:"Check for the openSUSE-2015-680 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"nodejs was updated to version 4.2.1 to fix one security issue.

This security issue was fixed :

  - CVE-2015-7384: HTTP Denial of Service Vulnerability
    (bsc#948602).

Various other issues were fixed, please see the changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=948045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=948602"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nodejs packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-npm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"nodejs-4.2.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"nodejs-debuginfo-4.2.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"nodejs-debugsource-4.2.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"nodejs-devel-4.2.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nodejs-4.2.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nodejs-debuginfo-4.2.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nodejs-debugsource-4.2.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nodejs-devel-4.2.1-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-4.2.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-debuginfo-4.2.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-debugsource-4.2.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-devel-4.2.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-npm-4.2.1-10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs / nodejs-debuginfo / nodejs-debugsource / nodejs-devel / etc");
}
