#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-5.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75093);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2012-5611");

  script_name(english:"openSUSE Security Update : mysql-community-server (openSUSE-SU-2013:0013-1)");
  script_summary(english:"Check for the openSUSE-2013-5 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"mysql community server was updated to 5.5.28, fixing bugs and security
issues. See http://dev.mysql.com/doc/refman/5.5/en/news-5-5-27.html
http://dev.mysql.com/doc/refman/5.5/en/news-5-5-28.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.5/en/news-5-5-27.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.5/en/news-5-5-28.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-01/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792444"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-community-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debug-version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debug-version-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"libmysqlclient-devel-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqlclient18-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqlclient18-debuginfo-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqlclient_r18-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqld-devel-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqld18-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqld18-debuginfo-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-bench-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-bench-debuginfo-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-client-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-client-debuginfo-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-debug-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-debug-debuginfo-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-debuginfo-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-debugsource-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-errormessages-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-test-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-test-debuginfo-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-tools-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-tools-debuginfo-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libmysqlclient-devel-32bit-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libmysqlclient18-32bit-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-5.5.28-3.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libmysqlclient-devel-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libmysqlclient18-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libmysqlclient18-debuginfo-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libmysqlclient_r18-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libmysqld-devel-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libmysqld18-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libmysqld18-debuginfo-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-bench-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-bench-debuginfo-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-client-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-client-debuginfo-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-debug-version-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-debug-version-debuginfo-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-debuginfo-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-debugsource-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-errormessages-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-test-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-test-debuginfo-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-tools-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-tools-debuginfo-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libmysqlclient18-32bit-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-5.5.28-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-5.5.28-1.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql-community-server");
}
