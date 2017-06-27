#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1814. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71337);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2011-1398", "CVE-2012-2688", "CVE-2013-1643", "CVE-2013-6420");
  script_bugtraq_id(54638, 55297, 58766);
  script_osvdb_id(84126, 85086, 90922, 100979);
  script_xref(name:"RHSA", value:"2013:1814");

  script_name(english:"RHEL 5 : php (RHSA-2013:1814)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

A memory corruption flaw was found in the way the openssl_x509_parse()
function of the PHP openssl extension parsed X.509 certificates. A
remote attacker could use this flaw to provide a malicious self-signed
certificate or a certificate signed by a trusted authority to a PHP
application using the aforementioned function, causing the application
to crash or, possibly, allow the attacker to execute arbitrary code
with the privileges of the user running the PHP interpreter.
(CVE-2013-6420)

It was found that PHP did not check for carriage returns in HTTP
headers, allowing intended HTTP response splitting protections to be
bypassed. Depending on the web browser the victim is using, a remote
attacker could use this flaw to perform HTTP response splitting
attacks. (CVE-2011-1398)

An integer signedness issue, leading to a heap-based buffer underflow,
was found in the PHP scandir() function. If a remote attacker could
upload an excessively large number of files to a directory the
scandir() function runs on, it could cause the PHP interpreter to
crash or, possibly, execute arbitrary code. (CVE-2012-2688)

It was found that the PHP SOAP parser allowed the expansion of
external XML entities during SOAP message parsing. A remote attacker
could possibly use this flaw to read arbitrary files that are
accessible to a PHP application using a SOAP extension.
(CVE-2013-1643)

Red Hat would like to thank the PHP project for reporting
CVE-2013-6420. Upstream acknowledges Stefan Esser as the original
reporter.

All php users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1398.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2688.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1643.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1814.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-debuginfo");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:1814";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-bcmath-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-bcmath-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-bcmath-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-cli-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-cli-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-cli-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-common-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-common-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-common-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-dba-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-dba-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-dba-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-debuginfo-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-debuginfo-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-debuginfo-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-devel-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-devel-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-devel-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-gd-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-gd-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-gd-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-imap-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-imap-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-imap-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-ldap-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-ldap-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-ldap-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-mbstring-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-mbstring-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-mbstring-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-mysql-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-mysql-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-mysql-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-ncurses-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-ncurses-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-ncurses-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-odbc-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-odbc-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-odbc-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-pdo-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-pdo-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-pdo-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-pgsql-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-pgsql-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-pgsql-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-snmp-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-snmp-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-snmp-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-soap-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-soap-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-soap-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-xml-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-xml-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-xml-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php-xmlrpc-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php-xmlrpc-5.1.6-43.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php-xmlrpc-5.1.6-43.el5_10")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-debuginfo / etc");
  }
}
