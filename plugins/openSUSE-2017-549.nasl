#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-549.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(100036);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/09 15:19:41 $");

  script_cve_id("CVE-2015-0860");

  script_name(english:"openSUSE Security Update : dpkg (openSUSE-2017-549)");
  script_summary(english:"Check for the openSUSE-2017-549 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dpkg fixes the following issues :

This security issue was fixed :

  - CVE-2015-0860: Off-by-one error in the extracthalf
    function in dpkg-deb/extract.c in the dpkg-deb component
    in dpkg allowed remote attackers to execute arbitrary
    code via the archive magic version number in an
    'old-style' Debian binary package, which triggered a
    stack-based buffer overflow (bsc#957160).

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957160"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dpkg packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpkg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpkg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpkg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpkg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpkg-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:update-alternatives");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:update-alternatives-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:update-alternatives-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.1", reference:"dpkg-1.16.10-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dpkg-debuginfo-1.16.10-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dpkg-debugsource-1.16.10-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dpkg-devel-1.16.10-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dpkg-lang-1.16.10-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"update-alternatives-1.16.10-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"update-alternatives-debuginfo-1.16.10-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"update-alternatives-debugsource-1.16.10-14.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dpkg / dpkg-debuginfo / dpkg-debugsource / dpkg-devel / dpkg-lang / etc");
}
