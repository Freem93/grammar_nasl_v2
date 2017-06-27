#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libmysqlclient-devel-5341.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(33885);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2006-7232", "CVE-2008-2079");

  script_name(english:"openSUSE 10 Security Update : libmysqlclient-devel (libmysqlclient-devel-5341)");
  script_summary(english:"Check for the libmysqlclient-devel-5341 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The database server MySQL was updated to fix a security problem :

CVE-2008-2079: MySQL allowed local users to bypass certain privilege
checks by calling CREATE TABLE on a MyISAM table with modified (1)
DATA DIRECTORY or (2) INDEX DIRECTORY arguments that are within the
MySQL home data directory, which can point to tables that are created
in the future.

CVE-2006-7232: sql_select.cc in MySQL 5.0.x before 5.0.32 and 5.1.x
before 5.1.14 allows remote authenticated users to cause a denial of
service (crash) via an EXPLAIN SELECT FROM on the INFORMATION_SCHEMA
table, as originally demonstrated using ORDER BY."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libmysqlclient-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_cwe_id(89, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient15-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r15-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-Max");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-shared-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"mysql-5.0.26-12.17.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mysql-Max-5.0.26-12.17.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mysql-bench-5.0.26-12.17.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mysql-client-5.0.26-12.17.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mysql-devel-5.0.26-12.17.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mysql-shared-5.0.26-12.17.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"mysql-shared-32bit-5.0.26-12.17.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mysql-5.0.26-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mysql-Max-5.0.26-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mysql-bench-5.0.26-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mysql-client-5.0.26-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mysql-debug-5.0.26-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mysql-devel-5.0.26-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mysql-shared-5.0.26-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"mysql-shared-32bit-5.0.26-19") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libmysqlclient-devel-5.0.45-22.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libmysqlclient15-5.0.45-22.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libmysqlclient_r15-5.0.45-22.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mysql-5.0.45-22.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mysql-Max-5.0.45-22.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mysql-bench-5.0.45-22.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mysql-client-5.0.45-22.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mysql-debug-5.0.45-22.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mysql-tools-5.0.45-22.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"libmysqlclient15-32bit-5.0.45-22.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"libmysqlclient_r15-32bit-5.0.45-22.5") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql");
}
