#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:0311 and 
# Oracle Linux Security Advisory ELSA-2014-0311 respectively.
#

include("compat.inc");

if (description)
{
  script_id(73089);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/06 17:02:16 $");

  script_cve_id("CVE-2006-7243", "CVE-2009-0689");
  script_bugtraq_id(44951);
  script_osvdb_id(55603, 70606);
  script_xref(name:"RHSA", value:"2014:0311");

  script_name(english:"Oracle Linux 5 : php (ELSA-2014-0311)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:0311 :

Updated php packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
Critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

A buffer overflow flaw was found in the way PHP parsed floating point
numbers from their text representation. If a PHP application converted
untrusted input strings to numbers, an attacker able to provide such
input could cause the application to crash or, possibly, execute
arbitrary code with the privileges of the application. (CVE-2009-0689)

It was found that PHP did not properly handle file names with a NULL
character. A remote attacker could possibly use this flaw to make a
PHP script access unexpected files and bypass intended file system
access restrictions. (CVE-2006-7243)

All php users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-March/004025.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"php-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-bcmath-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-cli-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-common-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-dba-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-devel-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-gd-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-imap-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-ldap-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-mbstring-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-mysql-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-ncurses-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-odbc-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-pdo-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-pgsql-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-snmp-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-soap-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-xml-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"php-xmlrpc-5.1.6-44.el5_10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-devel / etc");
}
