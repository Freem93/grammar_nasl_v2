#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-332.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74654);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/13 15:25:35 $");

  script_cve_id("CVE-2012-2122");

  script_name(english:"openSUSE Security Update : mysql-community-server (openSUSE-2012-332)");
  script_summary(english:"Check for the openSUSE-2012-332 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Version upgrade to 5.5.25 of MySQL to fix an authentication bypass
flaw. Additionally, various other non-security bugs were fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765092"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-community-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.4", reference:"libmysqlclient-devel-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqlclient16-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqlclient16-debuginfo-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqlclient_r16-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqlclient_r16-debuginfo-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqld-devel-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqld0-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqld0-debuginfo-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-bench-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-bench-debuginfo-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-client-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-client-debuginfo-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-debug-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-debug-debuginfo-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-debuginfo-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-debugsource-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-test-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-test-debuginfo-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-tools-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-tools-debuginfo-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libmysqlclient16-32bit-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libmysqlclient16-debuginfo-32bit-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libmysqlclient_r16-32bit-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libmysqlclient_r16-debuginfo-32bit-5.1.63-55.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqlclient-devel-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqlclient18-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqlclient18-debuginfo-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqlclient_r18-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqld-devel-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqld18-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmysqld18-debuginfo-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-bench-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-bench-debuginfo-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-client-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-client-debuginfo-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-debug-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-debug-debuginfo-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-debuginfo-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-debugsource-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-test-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-test-debuginfo-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-tools-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mysql-community-server-tools-debuginfo-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libmysqlclient-devel-32bit-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libmysqlclient18-32bit-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-5.5.25-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-5.5.25-3.9.2") ) flag++;

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
