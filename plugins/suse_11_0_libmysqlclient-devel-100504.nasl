#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libmysqlclient-devel-2315.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(46229);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/21 20:09:50 $");

  script_cve_id("CVE-2008-7247", "CVE-2009-4019", "CVE-2009-4028", "CVE-2009-4030");

  script_name(english:"openSUSE Security Update : libmysqlclient-devel (openSUSE-SU-2010:0198-2)");
  script_summary(english:"Check for the libmysqlclient-devel-2315 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages fix the following bugs :

  - upstream #47320 - checking server certificates
    (CVE-2009-4028)

  - upstream #48291 - error handling in subqueries
    (CVE-2009-4019)

  - upstream #47780 - preserving null_value flag in
    GeomFromWKB() (CVE-2009-4019)

  - upstream #39277 - symlink behaviour fixed
    (CVE-2008-7247)

  - upstream #32167 - symlink behaviour refixed
    (CVE-2009-4030)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-05/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=557669"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libmysqlclient-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 59);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"libmysqlclient-devel-5.0.51a-27.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libmysqlclient15-5.0.51a-27.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libmysqlclient_r15-5.0.51a-27.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mysql-5.0.51a-27.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mysql-Max-5.0.51a-27.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mysql-bench-5.0.51a-27.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mysql-client-5.0.51a-27.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mysql-debug-5.0.51a-27.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mysql-tools-5.0.51a-27.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libmysqlclient15-32bit-5.0.51a-27.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libmysqlclient_r15-32bit-5.0.51a-27.8") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient-devel / libmysqlclient15 / libmysqlclient15-32bit / etc");
}
