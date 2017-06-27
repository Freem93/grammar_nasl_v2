#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1326 and 
# CentOS Errata and Security Advisory 2014:1326 respectively.
#

include("compat.inc");

if (description)
{
  script_id(77995);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2014-2497", "CVE-2014-3587", "CVE-2014-3597", "CVE-2014-4670", "CVE-2014-4698");
  script_bugtraq_id(66233, 68511, 68513, 69322, 69325);
  script_osvdb_id(79681, 104502, 108946, 108947, 110250, 110251);
  script_xref(name:"RHSA", value:"2014:1326");

  script_name(english:"CentOS 5 / 6 : php / php53 (CESA-2014:1326)");
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

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server. PHP's fileinfo module provides functions used to
identify a particular file according to the type of data contained by
the file.

It was found that the fix for CVE-2012-1571 was incomplete; the File
Information (fileinfo) extension did not correctly parse certain
Composite Document Format (CDF) files. A remote attacker could use
this flaw to crash a PHP application using fileinfo via a specially
crafted CDF file. (CVE-2014-3587)

A NULL pointer dereference flaw was found in the
gdImageCreateFromXpm() function of PHP's gd extension. A remote
attacker could use this flaw to crash a PHP application using gd via a
specially crafted X PixMap (XPM) file. (CVE-2014-2497)

Multiple buffer over-read flaws were found in the php_parserr()
function of PHP. A malicious DNS server or a man-in-the-middle
attacker could possibly use this flaw to execute arbitrary code as the
PHP interpreter if a PHP application used the dns_get_record()
function to perform a DNS query. (CVE-2014-3597)

Two use-after-free flaws were found in the way PHP handled certain
Standard PHP Library (SPL) Iterators and ArrayIterators. A malicious
script author could possibly use either of these flaws to disclose
certain portions of server memory. (CVE-2014-4670, CVE-2014-4698)

The CVE-2014-3597 issue was discovered by David Kutalek of the Red
Hat BaseOS QE.

All php53 and php users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
After installing the updated packages, the httpd daemon must be
restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-September/020602.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7c28e51"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-September/020654.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96d28f00"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php and / or php53 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"php53-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-bcmath-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-cli-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-common-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-dba-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-devel-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-gd-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-imap-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-intl-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-ldap-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-mbstring-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-mysql-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-odbc-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pdo-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pgsql-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-process-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pspell-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-snmp-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-soap-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-xml-5.3.3-24.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-xmlrpc-5.3.3-24.el5")) flag++;

if (rpm_check(release:"CentOS-6", reference:"php-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-bcmath-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-cli-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-common-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-dba-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-devel-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-embedded-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-enchant-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-fpm-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-gd-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-imap-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-intl-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-ldap-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mbstring-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mysql-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-odbc-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pdo-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pgsql-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-process-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pspell-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-recode-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-snmp-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-soap-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-tidy-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xml-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xmlrpc-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-zts-5.3.3-27.el6_5.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
