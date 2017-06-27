#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:687. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16041);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/28 17:55:17 $");

  script_cve_id("CVE-2004-0958", "CVE-2004-0959", "CVE-2004-1018", "CVE-2004-1019", "CVE-2004-1065");
  script_osvdb_id(12410, 12411, 12601, 12602, 12603);
  script_xref(name:"RHSA", value:"2004:687");

  script_name(english:"RHEL 3 : php (RHSA-2004:687)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix various security issues and bugs are now
available for Red Hat Enterprise Linux 3.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

Flaws including possible information disclosure, double free, and
negative reference index array underflow were found in the
deserialization code of PHP. PHP applications may use the unserialize
function on untrusted user data, which could allow a remote attacker
to gain access to memory or potentially execute arbitrary code. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-1019 to this issue.

A flaw in the exif extension of PHP was found which lead to a stack
overflow. An attacker could create a carefully crafted image file in
such a way that if parsed by a PHP script using the exif extension it
could cause a crash or potentially execute arbitrary code. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-1065 to this issue.

An information disclosure bug was discovered in the parsing of 'GPC'
variables in PHP (query strings or cookies, and POST form data). If
particular scripts used the values of the GPC variables, portions of
the memory space of an httpd child process could be revealed to the
client. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0958 to this issue.

A file access bug was discovered in the parsing of
'multipart/form-data' forms, used by PHP scripts which allow file
uploads. In particular configurations, some scripts could allow a
malicious client to upload files to an arbitrary directory where the
'apache' user has write access. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2004-0959
to this issue.

Flaws were found in shmop_write, pack, and unpack PHP functions. These
functions are not normally passed user-supplied data, so would require
a malicious PHP script to be exploited. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2004-1018
to this issue.

Various issues were discovered in the use of the 'select' system call
in PHP, which could be triggered if PHP is used in an Apache
configuration where the number of open files (such as virtual host log
files) exceeds the default process limit of 1024. Workarounds are now
included for some of these issues.

The 'phpize' shell script included in PHP can be used to build
third-party extension modules. A build issue was discovered in the
'phpize' script on some 64-bit platforms which prevented correct
operation.

The 'pcntl' extension module is now enabled in the command line PHP
interpreter, /usr/bin/php. This module enables process control
features such as 'fork' and 'kill' from PHP scripts.

Users of PHP should upgrade to these updated packages, which contain
fixes for these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0958.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0959.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1065.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-687.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:687";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL3", reference:"php-4.3.2-19.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-devel-4.3.2-19.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-imap-4.3.2-19.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-ldap-4.3.2-19.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-mysql-4.3.2-19.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-odbc-4.3.2-19.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-pgsql-4.3.2-19.ent")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-devel / php-imap / php-ldap / php-mysql / php-odbc / etc");
  }
}
