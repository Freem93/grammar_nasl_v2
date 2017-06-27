#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1012 and 
# CentOS Errata and Security Advisory 2014:1012 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(77032);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/31 01:51:50 $");

  script_cve_id("CVE-2012-1571", "CVE-2013-6712", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-1943", "CVE-2014-2270", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3515", "CVE-2014-4049", "CVE-2014-4721");
  script_bugtraq_id(52225, 64018, 65596, 66002, 67759, 67765, 68007, 68237, 68238, 68241, 68423);
  script_xref(name:"RHSA", value:"2014:1012");

  script_name(english:"CentOS 5 / 6 : php / php53 (CESA-2014:1012)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # http://lists.centos.org/pipermail/centos-announce/2014-August/020470.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35b27f2a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-August/020473.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d903b2aa"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php and / or php53 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-zts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php53-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"php53-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-bcmath-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-cli-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-common-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-dba-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-devel-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-gd-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-imap-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-intl-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-ldap-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-mbstring-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-mysql-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-odbc-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pdo-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pgsql-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-process-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pspell-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-snmp-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-soap-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-xml-5.3.3-23.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-xmlrpc-5.3.3-23.el5_10")) flag++;

if (rpm_check(release:"CentOS-6", reference:"php-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-bcmath-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-cli-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-common-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-dba-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-devel-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-embedded-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-enchant-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-fpm-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-gd-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-imap-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-intl-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-ldap-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mbstring-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mysql-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-odbc-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pdo-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pgsql-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-process-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pspell-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-recode-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-snmp-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-soap-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-tidy-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xml-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xmlrpc-5.3.3-27.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-zts-5.3.3-27.el6_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
