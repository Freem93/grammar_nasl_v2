#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:564. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18648);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/28 17:55:19 $");

  script_cve_id("CVE-2005-1751", "CVE-2005-1921");
  script_bugtraq_id(14088);
  script_osvdb_id(16848, 17793);
  script_xref(name:"RHSA", value:"2005:564");

  script_name(english:"RHEL 3 / 4 : php (RHSA-2005:564)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PHP packages that fix two security issues are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

A bug was discovered in the PEAR XML-RPC Server package included in
PHP. If a PHP script is used which implements an XML-RPC Server using
the PEAR XML-RPC package, then it is possible for a remote attacker to
construct an XML-RPC request which can cause PHP to execute arbitrary
PHP commands as the 'apache' user. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-1921
to this issue.

When using the default SELinux 'targeted' policy on Red Hat Enterprise
Linux 4, the impact of this issue is reduced since the scripts
executed by PHP are constrained within the httpd_sys_script_t security
context.

A race condition in temporary file handling was discovered in the
shtool script installed by PHP. If a third-party PHP module which uses
shtool was compiled as root, a local user may be able to modify
arbitrary files. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1751 to this issue.

Users of PHP should upgrade to these updated packages, which contain
backported fixes for these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1751.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1921.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-564.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP XML-RPC Arbitrary Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2005:564";
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
  if (rpm_check(release:"RHEL3", reference:"php-4.3.2-24.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-devel-4.3.2-24.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-imap-4.3.2-24.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-ldap-4.3.2-24.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-mysql-4.3.2-24.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-odbc-4.3.2-24.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-pgsql-4.3.2-24.ent")) flag++;

  if (rpm_check(release:"RHEL4", reference:"php-4.3.9-3.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-devel-4.3.9-3.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-domxml-4.3.9-3.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-gd-4.3.9-3.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-imap-4.3.9-3.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-ldap-4.3.9-3.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-mbstring-4.3.9-3.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-mysql-4.3.9-3.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-ncurses-4.3.9-3.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-odbc-4.3.9-3.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-pear-4.3.9-3.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-pgsql-4.3.9-3.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-snmp-4.3.9-3.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-xmlrpc-4.3.9-3.7")) flag++;

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
