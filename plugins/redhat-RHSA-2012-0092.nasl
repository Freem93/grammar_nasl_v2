#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0092. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57820);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/05 16:04:20 $");

  script_cve_id("CVE-2012-0830");
  script_bugtraq_id(51830);
  script_osvdb_id(78819);
  script_xref(name:"RHSA", value:"2012:0092");

  script_name(english:"RHEL 5 : php53 (RHSA-2012:0092)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php53 packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

It was discovered that the fix for CVE-2011-4885 (released via
RHSA-2012:0019 for php53 packages in Red Hat Enterprise Linux 5)
introduced an uninitialized memory use flaw. A remote attacker could
send a specially- crafted HTTP request to cause the PHP interpreter to
crash or, possibly, execute arbitrary code. (CVE-2012-0830)

All php53 users should upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing the
updated packages, the httpd daemon must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0830.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0092.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2012:0092";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-bcmath-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-bcmath-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-bcmath-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-cli-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-cli-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-cli-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-common-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-common-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-common-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-dba-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-dba-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-dba-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-devel-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-devel-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-devel-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-gd-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-gd-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-gd-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-imap-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-imap-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-imap-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-intl-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-intl-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-intl-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-ldap-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-ldap-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-ldap-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-mbstring-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-mbstring-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-mbstring-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-mysql-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-mysql-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-mysql-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-odbc-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-odbc-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-odbc-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-pdo-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-pdo-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-pdo-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-pgsql-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-pgsql-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-pgsql-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-process-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-process-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-process-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-pspell-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-pspell-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-pspell-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-snmp-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-snmp-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-snmp-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-soap-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-soap-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-soap-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-xml-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-xml-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-xml-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-xmlrpc-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-xmlrpc-5.3.3-1.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-xmlrpc-5.3.3-1.el5_7.6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php53 / php53-bcmath / php53-cli / php53-common / php53-dba / etc");
  }
}
