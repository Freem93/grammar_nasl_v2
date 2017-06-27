#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:0337 and 
# Oracle Linux Security Advisory ELSA-2009-0337 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67817);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/07 20:57:50 $");

  script_cve_id("CVE-2008-3658", "CVE-2008-3660", "CVE-2008-5498", "CVE-2008-5557", "CVE-2009-0754");
  script_bugtraq_id(30649, 31612, 32948, 33002, 33542);
  script_osvdb_id(47798);
  script_xref(name:"RHSA", value:"2009:0337");

  script_name(english:"Oracle Linux 3 / 4 : php (ELSA-2009-0337)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:0337 :

Updated php packages that fix several security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

A heap-based buffer overflow flaw was found in PHP's mbstring
extension. A remote attacker able to pass arbitrary input to a PHP
script using mbstring conversion functions could cause the PHP
interpreter to crash or, possibly, execute arbitrary code.
(CVE-2008-5557)

A flaw was found in the handling of the 'mbstring.func_overload'
configuration setting. A value set for one virtual host, or in a
user's .htaccess file, was incorrectly applied to other virtual hosts
on the same server, causing the handling of multibyte character
strings to not work correctly. (CVE-2009-0754)

A buffer overflow flaw was found in PHP's imageloadfont function. If a
PHP script allowed a remote attacker to load a carefully crafted font
file, it could cause the PHP interpreter to crash or, possibly,
execute arbitrary code. (CVE-2008-3658)

A flaw was found in the way PHP handled certain file extensions when
running in FastCGI mode. If the PHP interpreter was being executed via
FastCGI, a remote attacker could create a request which would cause
the PHP interpreter to crash. (CVE-2008-3660)

A memory disclosure flaw was found in the PHP gd extension's
imagerotate function. A remote attacker able to pass arbitrary values
as the 'background color' argument of the function could, possibly,
view portions of the PHP interpreter's memory. (CVE-2008-5498)

All php users are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues. The httpd web
server must be restarted for the changes to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-April/000951.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-April/000952.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 134, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-domxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"php-4.3.2-51.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"php-4.3.2-51.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"php-devel-4.3.2-51.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"php-devel-4.3.2-51.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"php-imap-4.3.2-51.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"php-imap-4.3.2-51.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"php-ldap-4.3.2-51.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"php-ldap-4.3.2-51.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"php-mysql-4.3.2-51.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"php-mysql-4.3.2-51.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"php-odbc-4.3.2-51.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"php-odbc-4.3.2-51.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"php-pgsql-4.3.2-51.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"php-pgsql-4.3.2-51.ent")) flag++;

if (rpm_check(release:"EL4", reference:"php-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"EL4", reference:"php-devel-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"EL4", reference:"php-domxml-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"EL4", reference:"php-gd-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"EL4", reference:"php-imap-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"EL4", reference:"php-ldap-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"EL4", reference:"php-mbstring-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"EL4", reference:"php-mysql-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"EL4", reference:"php-ncurses-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"EL4", reference:"php-odbc-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"EL4", reference:"php-pear-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"EL4", reference:"php-pgsql-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"EL4", reference:"php-snmp-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"EL4", reference:"php-xmlrpc-4.3.9-3.22.15")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-devel / php-domxml / php-gd / php-imap / php-ldap / etc");
}
