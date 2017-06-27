#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-4.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75036);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2012-4414", "CVE-2012-5611");

  script_name(english:"openSUSE Security Update : mariadb (openSUSE-SU-2013:0014-1)");
  script_summary(english:"Check for the openSUSE-2013-4 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MariaDB was updated to 5.2.13.

  - Release notes:
    http://kb.askmonty.org/v/mariadb-5213-release-notes

  - Changelog:
    http://kb.askmonty.org/v/mariadb-5213-changelog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kb.askmonty.org/v/mariadb-5213-changelog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kb.askmonty.org/v/mariadb-5213-release-notes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-01/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792444"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadbclient16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadbclient16-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadbclient_r16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadbclient_r16-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/23");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"libmariadbclient16-5.2.13-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmariadbclient16-debuginfo-5.2.13-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmariadbclient_r16-5.2.13-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmariadbclient_r16-debuginfo-5.2.13-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-5.2.13-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-bench-5.2.13-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-bench-debuginfo-5.2.13-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-client-5.2.13-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-client-debuginfo-5.2.13-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-debug-5.2.13-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-debug-debuginfo-5.2.13-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-debuginfo-5.2.13-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-debugsource-5.2.13-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-test-5.2.13-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-test-debuginfo-5.2.13-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-tools-5.2.13-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-tools-debuginfo-5.2.13-2.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb");
}
