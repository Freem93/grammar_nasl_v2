#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-274.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74624);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2011-2262", "CVE-2012-0075", "CVE-2012-0087", "CVE-2012-0101", "CVE-2012-0102", "CVE-2012-0112", "CVE-2012-0113", "CVE-2012-0114", "CVE-2012-0115", "CVE-2012-0116", "CVE-2012-0118", "CVE-2012-0119", "CVE-2012-0120", "CVE-2012-0484", "CVE-2012-0485", "CVE-2012-0490", "CVE-2012-0492", "CVE-2012-0583", "CVE-2012-1688", "CVE-2012-1690", "CVE-2012-1703");

  script_name(english:"openSUSE Security Update : mariadb (openSUSE-2012-274)");
  script_summary(english:"Check for the openSUSE-2012-274 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"mariadb update to version 5.2.12 fixes several security issues and
bugs. Please refer to the following upstream announcements for 
details :

http://kb.askmonty.org/v/mariadb-5212-release-notes
http://kb.askmonty.org/v/mariadb-5211-release-notes
http://kb.askmonty.org/v/mariadb-5210-release-notes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kb.askmonty.org/en/changelogs-mariadb-51-series"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kb.askmonty.org/v/mariadb-5210-release-notes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kb.askmonty.org/v/mariadb-5211-release-notes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kb.askmonty.org/v/mariadb-5212-release-notes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-05/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=675870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=734436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=742272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758460"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"libmariadbclient16-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmariadbclient16-debuginfo-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmariadbclient_r16-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmariadbclient_r16-debuginfo-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mariadb-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mariadb-bench-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mariadb-bench-debuginfo-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mariadb-client-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mariadb-client-debuginfo-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mariadb-debug-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mariadb-debug-debuginfo-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mariadb-debuginfo-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mariadb-debugsource-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mariadb-test-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mariadb-test-debuginfo-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mariadb-tools-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mariadb-tools-debuginfo-5.1.62-39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmariadbclient16-5.2.12-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmariadbclient16-debuginfo-5.2.12-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmariadbclient_r16-5.2.12-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmariadbclient_r16-debuginfo-5.2.12-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-5.2.12-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-bench-5.2.12-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-bench-debuginfo-5.2.12-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-client-5.2.12-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-client-debuginfo-5.2.12-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-debug-5.2.12-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-debug-debuginfo-5.2.12-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-debuginfo-5.2.12-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-debugsource-5.2.12-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-test-5.2.12-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-test-debuginfo-5.2.12-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-tools-5.2.12-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mariadb-tools-debuginfo-5.2.12-2.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmariadbclient16 / libmariadbclient16-debuginfo / etc");
}
