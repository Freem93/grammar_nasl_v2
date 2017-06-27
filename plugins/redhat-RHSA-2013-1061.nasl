#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1061. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79287);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/05 16:29:43 $");

  script_cve_id("CVE-2013-4113");
  script_bugtraq_id(61128);
  script_osvdb_id(95152);
  script_xref(name:"RHSA", value:"2013:1061");

  script_name(english:"RHEL 5 / 6 : php (RHSA-2013:1061)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix one security issue are now available for
Red Hat Enterprise Linux 5.3 Long Life, and Red Hat Enterprise Linux
5.6, 6.2 and 6.3 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

A buffer overflow flaw was found in the way PHP parsed deeply nested
XML documents. If a PHP application used the xml_parse_into_struct()
function to parse untrusted XML content, an attacker able to supply
specially crafted XML could use this flaw to crash the application or,
possibly, execute arbitrary code with the privileges of the user
running the PHP interpreter. (CVE-2013-4113)

All php users should upgrade to these updated packages, which contain
a backported patch to resolve this issue. After installing the updated
packages, the httpd daemon must be restarted for the update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4113.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1061.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-zts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.3|5\.6|6\.2|6\.3)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.3 / 5.6 / 6.2 / 6.3", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1061";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
{  sp = get_kb_item("Host/RedHat/minor_release");
  if (isnull(sp)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");

  flag = 0;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-bcmath-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-bcmath-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-bcmath-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-bcmath-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-bcmath-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-cli-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-cli-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-cli-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-cli-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-cli-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-common-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-common-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-common-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-common-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-common-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-dba-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-dba-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-dba-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-dba-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-dba-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-debuginfo-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-debuginfo-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-debuginfo-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-debuginfo-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-debuginfo-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-devel-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-devel-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-devel-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-devel-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-devel-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-gd-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-gd-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-gd-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-gd-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-gd-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-imap-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-imap-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-imap-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-imap-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-imap-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-ldap-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-ldap-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-ldap-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-ldap-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-ldap-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-mbstring-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-mbstring-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-mbstring-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-mbstring-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-mbstring-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-mysql-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-mysql-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-mysql-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-mysql-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-mysql-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-ncurses-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-ncurses-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-ncurses-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-ncurses-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-ncurses-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-odbc-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-odbc-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-odbc-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-odbc-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-odbc-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-pdo-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-pdo-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-pdo-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-pdo-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-pdo-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-pgsql-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-pgsql-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-pgsql-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-pgsql-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-pgsql-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-snmp-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-snmp-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-snmp-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-snmp-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-snmp-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-soap-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-soap-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-soap-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-soap-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-soap-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-xml-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-xml-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-xml-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-xml-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-xml-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"php-xmlrpc-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"php-xmlrpc-5.1.6-23.4.el5_3")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"php-xmlrpc-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"php-xmlrpc-5.1.6-27.el5_6.5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"php-xmlrpc-5.1.6-23.4.el5_3")) flag++;

  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-bcmath-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-bcmath-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-bcmath-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-bcmath-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-bcmath-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-bcmath-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-cli-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-cli-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-cli-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-cli-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-cli-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-cli-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-common-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-common-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-common-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-common-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-common-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-common-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-dba-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-dba-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-dba-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-dba-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-dba-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-dba-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-debuginfo-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-debuginfo-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-debuginfo-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-debuginfo-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-debuginfo-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-debuginfo-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-devel-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-devel-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-devel-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-devel-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-devel-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-devel-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-embedded-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-embedded-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-embedded-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-embedded-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-embedded-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-embedded-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-enchant-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-enchant-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-enchant-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-enchant-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-enchant-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-enchant-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-gd-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-gd-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-gd-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-gd-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-gd-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-gd-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-imap-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-imap-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-imap-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-imap-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-imap-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-imap-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-intl-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-intl-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-intl-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-intl-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-intl-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-intl-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-ldap-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-ldap-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-ldap-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-ldap-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-ldap-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-ldap-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-mbstring-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-mbstring-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-mbstring-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-mbstring-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-mbstring-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-mbstring-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-mysql-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-mysql-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-mysql-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-mysql-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-mysql-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-mysql-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-odbc-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-odbc-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-odbc-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-odbc-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-odbc-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-odbc-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-pdo-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-pdo-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-pdo-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-pdo-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-pdo-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-pdo-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-pgsql-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-pgsql-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-pgsql-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-pgsql-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-pgsql-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-pgsql-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-process-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-process-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-process-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-process-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-process-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-process-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-pspell-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-pspell-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-pspell-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-pspell-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-pspell-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-pspell-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-recode-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-recode-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-recode-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-recode-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-recode-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-recode-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-snmp-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-snmp-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-snmp-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-snmp-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-snmp-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-snmp-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-soap-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-soap-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-soap-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-soap-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-soap-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-soap-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-tidy-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-tidy-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-tidy-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-tidy-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-tidy-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-tidy-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-xml-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-xml-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-xml-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-xml-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-xml-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-xml-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-xmlrpc-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-xmlrpc-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-xmlrpc-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-xmlrpc-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-xmlrpc-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-xmlrpc-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"i686", reference:"php-zts-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"php-zts-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"s390x", reference:"php-zts-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"s390x", reference:"php-zts-5.3.3-3.el6_2.10")) flag++;
  if (rpm_check(release:"RHEL6", sp:"3", cpu:"x86_64", reference:"php-zts-5.3.3-14.el6_3.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"php-zts-5.3.3-3.el6_2.10")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-debuginfo / etc");
  }
}
