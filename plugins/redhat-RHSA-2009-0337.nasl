#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0337. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36097);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/01/03 17:27:01 $");

  script_cve_id("CVE-2008-3658", "CVE-2008-3660", "CVE-2008-5498", "CVE-2008-5557", "CVE-2009-0754");
  script_bugtraq_id(30649, 31612, 32948, 33002, 33542);
  script_osvdb_id(47798);
  script_xref(name:"RHSA", value:"2009:0337");

  script_name(english:"RHEL 3 / 4 : php (RHSA-2009:0337)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix several security issues are now
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
    value:"https://www.redhat.com/security/data/cve/CVE-2008-3658.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-3660.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5498.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5557.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0754.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-0337.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 134, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-domxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:0337";
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
  if (rpm_check(release:"RHEL3", reference:"php-4.3.2-51.ent")) flag++;

  if (rpm_check(release:"RHEL3", reference:"php-devel-4.3.2-51.ent")) flag++;

  if (rpm_check(release:"RHEL3", reference:"php-imap-4.3.2-51.ent")) flag++;

  if (rpm_check(release:"RHEL3", reference:"php-ldap-4.3.2-51.ent")) flag++;

  if (rpm_check(release:"RHEL3", reference:"php-mysql-4.3.2-51.ent")) flag++;

  if (rpm_check(release:"RHEL3", reference:"php-odbc-4.3.2-51.ent")) flag++;

  if (rpm_check(release:"RHEL3", reference:"php-pgsql-4.3.2-51.ent")) flag++;


  if (rpm_check(release:"RHEL4", reference:"php-4.3.9-3.22.15")) flag++;

  if (rpm_check(release:"RHEL4", reference:"php-devel-4.3.9-3.22.15")) flag++;

  if (rpm_check(release:"RHEL4", reference:"php-domxml-4.3.9-3.22.15")) flag++;

  if (rpm_check(release:"RHEL4", reference:"php-gd-4.3.9-3.22.15")) flag++;

  if (rpm_check(release:"RHEL4", reference:"php-imap-4.3.9-3.22.15")) flag++;

  if (rpm_check(release:"RHEL4", reference:"php-ldap-4.3.9-3.22.15")) flag++;

  if (rpm_check(release:"RHEL4", reference:"php-mbstring-4.3.9-3.22.15")) flag++;

  if (rpm_check(release:"RHEL4", reference:"php-mysql-4.3.9-3.22.15")) flag++;

  if (rpm_check(release:"RHEL4", reference:"php-ncurses-4.3.9-3.22.15")) flag++;

  if (rpm_check(release:"RHEL4", reference:"php-odbc-4.3.9-3.22.15")) flag++;

  if (rpm_check(release:"RHEL4", reference:"php-pear-4.3.9-3.22.15")) flag++;

  if (rpm_check(release:"RHEL4", reference:"php-pgsql-4.3.9-3.22.15")) flag++;

  if (rpm_check(release:"RHEL4", reference:"php-snmp-4.3.9-3.22.15")) flag++;

  if (rpm_check(release:"RHEL4", reference:"php-xmlrpc-4.3.9-3.22.15")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-devel / php-domxml / php-gd / php-imap / php-ldap / etc");
  }
}
