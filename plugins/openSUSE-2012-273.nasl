#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-273.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74623);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2011-2262", "CVE-2012-0075", "CVE-2012-0087", "CVE-2012-0101", "CVE-2012-0102", "CVE-2012-0112", "CVE-2012-0113", "CVE-2012-0114", "CVE-2012-0115", "CVE-2012-0116", "CVE-2012-0117", "CVE-2012-0118", "CVE-2012-0119", "CVE-2012-0120", "CVE-2012-0484", "CVE-2012-0485", "CVE-2012-0486", "CVE-2012-0487", "CVE-2012-0488", "CVE-2012-0489", "CVE-2012-0490", "CVE-2012-0491", "CVE-2012-0492", "CVE-2012-0493", "CVE-2012-0494", "CVE-2012-0495", "CVE-2012-0496", "CVE-2012-0583", "CVE-2012-1688", "CVE-2012-1690", "CVE-2012-1696", "CVE-2012-1697", "CVE-2012-1703");

  script_name(english:"openSUSE Security Update : mysql-community-server (openSUSE-2012-273)");
  script_summary(english:"Check for the openSUSE-2012-273 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"mysql update to version 5.5.23 fixes several security issues and bugs.
Please refer to the following upstream announcements for details :

  - http://dev.mysql.com/doc/refman/5.5/en/news-5-5-16.html

  - http://dev.mysql.com/doc/refman/5.5/en/news-5-5-17.html

  - http://dev.mysql.com/doc/refman/5.5/en/news-5-5-18.html

  - http://dev.mysql.com/doc/refman/5.5/en/news-5-5-19.html

  - http://dev.mysql.com/doc/refman/5.5/en/news-5-5-20.html

  - http://dev.mysql.com/doc/refman/5.5/en/news-5-5-21.html

  - http://dev.mysql.com/doc/refman/5.5/en/news-5-5-22.html

  - http://dev.mysql.com/doc/refman/5.5/en/news-5-5-23.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-58.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-59.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-60.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-61.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-62.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.5/en/news-5-5-16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.5/en/news-5-5-17.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.5/en/news-5-5-18.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.5/en/news-5-5-19.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.5/en/news-5-5-20.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.5/en/news-5-5-21.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.5/en/news-5-5-22.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.5/en/news-5-5-23.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-05/msg00019.html"
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
    value:"Update the affected mysql-community-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient16-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient16-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient16-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r16-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r16-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r16-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools-debuginfo");
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

if ( rpm_check(release:"SUSE11.4", reference:"libmysqlclient-devel-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqlclient16-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqlclient16-debuginfo-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqlclient_r16-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqlclient_r16-debuginfo-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqld-devel-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqld0-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqld0-debuginfo-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-bench-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-bench-debuginfo-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-client-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-client-debuginfo-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-debug-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-debug-debuginfo-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-debuginfo-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-debugsource-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-test-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-test-debuginfo-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-tools-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-tools-debuginfo-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libmysqlclient16-32bit-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libmysqlclient16-debuginfo-32bit-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libmysqlclient_r16-32bit-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libmysqlclient_r16-debuginfo-32bit-5.1.62-52.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqlclient-devel-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqlclient18-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqlclient18-debuginfo-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqlclient_r18-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqld-devel-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqld18-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqld18-debuginfo-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-bench-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-bench-debuginfo-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-client-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-client-debuginfo-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-debug-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-debug-debuginfo-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-debuginfo-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-debugsource-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-test-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-test-debuginfo-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-tools-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-tools-debuginfo-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libmysqlclient-devel-32bit-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libmysqlclient18-32bit-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-5.5.23-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-5.5.23-3.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient-devel / libmysqlclient16-32bit / libmysqlclient16 / etc");
}
