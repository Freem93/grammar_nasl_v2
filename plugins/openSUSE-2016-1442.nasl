#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1442.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95748);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/06 14:38:26 $");

  script_cve_id("CVE-2016-7969", "CVE-2016-7972");

  script_name(english:"openSUSE Security Update : libass (openSUSE-2016-1442)");
  script_summary(english:"Check for the openSUSE-2016-1442 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libass fixes the following issues :

  - Fixed situations that could cause uninitialised memory
    to be used, leading to undefined behaviour.
    (boo#1002982, CVE-2016-7969, CVE-2016-7972)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002982"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libass packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libass-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libass-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libass5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libass5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libass5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libass5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libass-debugsource-0.12.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libass-devel-0.12.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libass5-0.12.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libass5-debuginfo-0.12.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libass5-32bit-0.12.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libass5-debuginfo-32bit-0.12.1-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libass-debugsource-0.12.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libass-devel-0.12.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libass5-0.12.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libass5-debuginfo-0.12.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libass5-32bit-0.12.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libass5-debuginfo-32bit-0.12.3-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libass-debugsource / libass-devel / libass5 / libass5-32bit / etc");
}
