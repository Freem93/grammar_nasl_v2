#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-13.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96295);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/21 13:44:39 $");

  script_cve_id("CVE-2016-9957", "CVE-2016-9958", "CVE-2016-9959", "CVE-2016-9960", "CVE-2016-9961");

  script_name(english:"openSUSE Security Update : libgme (openSUSE-2017-13)");
  script_summary(english:"Check for the openSUSE-2017-13 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libgme fixes the following issues :

  - CVE-2016-9957, CVE-2016-9958, CVE-2016-9959,
    CVE-2016-9960, CVE-2016-9961: Various issues were fixed
    in the handling of SPC music files that could have been
    exploited for gaining privileges of desktop users.
    [bsc#1015941]

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015941"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgme packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgme-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgme-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgme0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgme0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgme0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgme0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/05");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libgme-debugsource-0.6.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgme-devel-0.6.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgme0-0.6.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgme0-debuginfo-0.6.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgme0-32bit-0.6.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgme0-debuginfo-32bit-0.6.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgme-debugsource-0.6.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgme-devel-0.6.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgme0-0.6.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgme0-debuginfo-0.6.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgme0-32bit-0.6.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgme0-debuginfo-32bit-0.6.0-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgme-debugsource / libgme-devel / libgme0 / libgme0-32bit / etc");
}
