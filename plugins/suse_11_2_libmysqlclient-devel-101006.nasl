#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libmysqlclient-devel-3260.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(50016);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/13 20:00:36 $");

  script_cve_id("CVE-2010-1621", "CVE-2010-1626", "CVE-2010-1848", "CVE-2010-1849", "CVE-2010-1850", "CVE-2010-2008", "CVE-2010-3675", "CVE-2010-3676", "CVE-2010-3677", "CVE-2010-3678", "CVE-2010-3679", "CVE-2010-3680", "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3683");

  script_name(english:"openSUSE Security Update : libmysqlclient-devel (openSUSE-SU-2010:0730-1)");
  script_summary(english:"Check for the libmysqlclient-devel-3260 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - local users could delete data files for tables of other
    users (CVE-2010-1626).

  - authenticated users could gather information for tables
    they should not have access to (CVE-2010-1849)

  - authenticated users could crash mysqld (CVE-2010-1848)

  - authenticated users could potentially execute arbitrary
    code as the user running mysqld (CVE-2010-1850)

  - authenticated users could crash mysqld (CVE-2010-3676,
    CVE-2010-3677, CVE-2010-3678, CVE-2010-3679,
    CVE-2010-3680, CVE-2010-3681, CVE-2010-3682,
    CVE-2010-3683, CVE-2010-2008)

  - a race condition in /etc/init.d/mysql allowed local
    users to make any file readable via symlink in /var/tmp
    (CVE-2010-3675)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-10/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=582656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=607466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=609551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=637499"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libmysqlclient-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient16-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r16-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-ndb-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-ndb-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-ndb-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-ndb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"libmysqlclient-devel-5.1.49-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libmysqlclient16-5.1.49-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libmysqlclient_r16-5.1.49-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libmysqld-devel-5.1.49-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mysql-5.1.49-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mysql-bench-5.1.49-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mysql-client-5.1.49-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mysql-debug-5.1.49-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mysql-ndb-extra-5.1.49-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mysql-ndb-management-5.1.49-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mysql-ndb-storage-5.1.49-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mysql-ndb-tools-5.1.49-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mysql-test-5.1.49-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mysql-tools-5.1.49-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"libmysqlclient16-32bit-5.1.49-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"libmysqlclient_r16-32bit-5.1.49-0.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient-devel / libmysqlclient16 / libmysqlclient16-32bit / etc");
}
