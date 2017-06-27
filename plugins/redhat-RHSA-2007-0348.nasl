#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0348. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25334);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/29 15:35:21 $");

  script_cve_id("CVE-2007-1864", "CVE-2007-2509", "CVE-2007-2510");
  script_bugtraq_id(23813);
  script_xref(name:"RHSA", value:"2007:0348");

  script_name(english:"RHEL 5 : php (RHSA-2007:0348)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PHP packages that fix several security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

A heap buffer overflow flaw was found in the PHP 'xmlrpc' extension. A
PHP script which implements an XML-RPC server using this extension
could allow a remote attacker to execute arbitrary code as the
'apache' user. Note that this flaw does not affect PHP applications
using the pure-PHP XML_RPC class provided in /usr/share/pear.
(CVE-2007-1864)

A flaw was found in the PHP 'ftp' extension. If a PHP script used this
extension to provide access to a private FTP server, and passed
untrusted script input directly to any function provided by this
extension, a remote attacker would be able to send arbitrary FTP
commands to the server. (CVE-2007-2509)

A buffer overflow flaw was found in the PHP 'soap' extension,
regarding the handling of an HTTP redirect response when using the
SOAP client provided by this extension with an untrusted SOAP server.
No mechanism to trigger this flaw remotely is known. (CVE-2007-2510)

Users of PHP should upgrade to these updated packages which contain
backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-1864.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2509.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2510.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0348.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0348";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-bcmath-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-bcmath-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-bcmath-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-cli-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-cli-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-cli-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-common-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-common-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-common-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-dba-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-dba-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-dba-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-devel-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-devel-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-devel-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-gd-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-gd-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-gd-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-imap-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-imap-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-imap-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-ldap-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-ldap-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-ldap-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-mbstring-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-mbstring-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-mbstring-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-mysql-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-mysql-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-mysql-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-ncurses-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-ncurses-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-ncurses-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-odbc-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-odbc-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-odbc-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-pdo-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-pdo-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-pdo-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-pgsql-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-pgsql-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-pgsql-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-snmp-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-snmp-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-snmp-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-soap-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-soap-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-soap-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-xml-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-xml-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-xml-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-xmlrpc-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-xmlrpc-5.1.6-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-xmlrpc-5.1.6-12.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-devel / etc");
  }
}
