#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1012. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77015);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/06 15:40:58 $");

  script_cve_id("CVE-2012-1571", "CVE-2013-6712", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-1943", "CVE-2014-2270", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3515", "CVE-2014-4049", "CVE-2014-4721");
  script_bugtraq_id(52225, 64018, 65596, 66002, 67759, 67765, 68007, 68237, 68238, 68241, 68423);
  script_xref(name:"RHSA", value:"2014:1012");

  script_name(english:"RHEL 5 / 6 : php53 and php (RHSA-2014:1012)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php53 and php packages that fix multiple security issues are
now available for Red Hat Enterprise Linux 5 and 6 respectively.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server. PHP's fileinfo module provides functions used to
identify a particular file according to the type of data contained by
the file.

Multiple denial of service flaws were found in the way the File
Information (fileinfo) extension parsed certain Composite Document
Format (CDF) files. A remote attacker could use either of these flaws
to crash a PHP application using fileinfo via a specially crafted CDF
file. (CVE-2014-0237, CVE-2014-0238, CVE-2014-3479, CVE-2014-3480,
CVE-2012-1571)

Two denial of service flaws were found in the way the File Information
(fileinfo) extension handled indirect and search rules. A remote
attacker could use either of these flaws to cause a PHP application
using fileinfo to crash or consume an excessive amount of CPU.
(CVE-2014-1943, CVE-2014-2270)

A heap-based buffer overflow flaw was found in the way PHP parsed DNS
TXT records. A malicious DNS server or a man-in-the-middle attacker
could possibly use this flaw to execute arbitrary code as the PHP
interpreter if a PHP application used the dns_get_record() function to
perform a DNS query. (CVE-2014-4049)

A type confusion issue was found in PHP's phpinfo() function. A
malicious script author could possibly use this flaw to disclose
certain portions of server memory. (CVE-2014-4721)

A buffer over-read flaw was found in the way the DateInterval class
parsed interval specifications. An attacker able to make a PHP
application parse a specially crafted specification using DateInterval
could possibly cause the PHP interpreter to crash. (CVE-2013-6712)

A type confusion issue was found in the SPL ArrayObject and
SPLObjectStorage classes' unserialize() method. A remote attacker able
to submit specially crafted input to a PHP application, which would
then unserialize this input using one of the aforementioned methods,
could use this flaw to execute arbitrary code with the privileges of
the user running that PHP application. (CVE-2014-3515)

The CVE-2014-0237, CVE-2014-0238, CVE-2014-3479, and CVE-2014-3480
issues were discovered by Francisco Alonso of Red Hat Product
Security.

All php53 and php users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1571.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6712.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0237.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0238.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-1943.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2270.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3479.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3480.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3515.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4049.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4721.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1012.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysql");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/06");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1012";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-bcmath-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-bcmath-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-bcmath-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-cli-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-cli-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-cli-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-common-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-common-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-common-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-dba-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-dba-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-dba-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-debuginfo-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-debuginfo-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-debuginfo-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-devel-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-devel-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-devel-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-gd-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-gd-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-gd-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-imap-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-imap-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-imap-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-intl-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-intl-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-intl-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-ldap-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-ldap-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-ldap-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-mbstring-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-mbstring-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-mbstring-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-mysql-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-mysql-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-mysql-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-odbc-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-odbc-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-odbc-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-pdo-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-pdo-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-pdo-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-pgsql-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-pgsql-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-pgsql-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-process-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-process-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-process-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-pspell-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-pspell-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-pspell-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-snmp-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-snmp-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-snmp-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-soap-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-soap-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-soap-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-xml-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-xml-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-xml-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"php53-xmlrpc-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"php53-xmlrpc-5.3.3-23.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"php53-xmlrpc-5.3.3-23.el5_10")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-bcmath-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-bcmath-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-bcmath-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-cli-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-cli-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-cli-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-common-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-common-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-common-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-dba-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-dba-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-dba-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-debuginfo-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-debuginfo-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-debuginfo-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-devel-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-devel-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-devel-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-embedded-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-embedded-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-embedded-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-enchant-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-enchant-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-enchant-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-fpm-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-fpm-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-fpm-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-gd-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-gd-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-gd-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-imap-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-imap-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-imap-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-intl-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-intl-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-intl-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-ldap-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-ldap-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-ldap-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-mbstring-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-mbstring-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-mbstring-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-mysql-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-mysql-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-mysql-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-odbc-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-odbc-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-odbc-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pdo-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pdo-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pdo-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pgsql-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pgsql-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pgsql-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-process-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-process-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-process-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pspell-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pspell-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pspell-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-recode-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-recode-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-recode-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-snmp-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-snmp-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-snmp-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-soap-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-soap-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-soap-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-tidy-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-tidy-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-tidy-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-xml-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-xml-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-xml-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-xmlrpc-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-xmlrpc-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-xmlrpc-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-zts-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-zts-5.3.3-27.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-zts-5.3.3-27.el6_5.1")) flag++;


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
