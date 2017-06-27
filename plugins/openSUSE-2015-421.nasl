#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-421.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(84187);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/06/15 14:00:51 $");

  script_cve_id("CVE-2015-0840");

  script_name(english:"openSUSE Security Update : dpkg / update-alternatives (openSUSE-2015-421)");
  script_summary(english:"Check for the openSUSE-2015-421 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"dpkg and update-alternatives were updated to 1.16.16 to fix one
security issue and severan non-security bugs.

The following vulnerabilities were fixed :

  - CVE-2015-0840: Specially crafted deb packages could have
    been used to bypass source package integrity
    verification in local installs (boo#926749)

Also contains a number of upstream bugs and improvements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=926749"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dpkg / update-alternatives packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpkg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpkg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpkg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpkg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dpkg-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:update-alternatives");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:update-alternatives-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:update-alternatives-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/15");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"dpkg-1.16.16-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dpkg-debuginfo-1.16.16-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dpkg-debugsource-1.16.16-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dpkg-devel-1.16.16-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dpkg-lang-1.16.16-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"update-alternatives-1.16.16-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"update-alternatives-debuginfo-1.16.16-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"update-alternatives-debugsource-1.16.16-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dpkg-1.16.16-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dpkg-debuginfo-1.16.16-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dpkg-debugsource-1.16.16-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dpkg-devel-1.16.16-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"dpkg-lang-1.16.16-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"update-alternatives-1.16.16-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"update-alternatives-debuginfo-1.16.16-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"update-alternatives-debugsource-1.16.16-8.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dpkg / dpkg-debuginfo / dpkg-debugsource / dpkg-devel / dpkg-lang / etc");
}
