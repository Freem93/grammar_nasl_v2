#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1613 and 
# CentOS Errata and Security Advisory 2016:1613 respectively.
#

include("compat.inc");

if (description)
{
  script_id(92952);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2016-5385");
  script_osvdb_id(141667);
  script_xref(name:"RHSA", value:"2016:1613");

  script_name(english:"CentOS 7 : php (CESA-2016:1613) (httpoxy)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for php is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

Security Fix(es) :

* It was discovered that PHP did not properly protect against the
HTTP_PROXY variable name clash. A remote attacker could possibly use
this flaw to redirect HTTP requests performed by a PHP script to an
attacker-controlled proxy via a malicious HTTP request.
(CVE-2016-5385)

Red Hat would like to thank Scott Geary (VendHQ) for reporting this
issue.

Bug Fix(es) :

* Previously, an incorrect logic in the SAPI header callback routine
caused that the callback counter was not incremented. Consequently,
when a script included a header callback, it could terminate
unexpectedly with a segmentation fault. With this update, the callback
counter is properly managed, and scripts with a header callback
implementation work as expected. (BZ#1346758)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-August/022036.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ec9191b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-bcmath-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-cli-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-common-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-dba-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-devel-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-embedded-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-enchant-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-fpm-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-gd-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-intl-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-ldap-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-mbstring-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-mysql-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-mysqlnd-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-odbc-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-pdo-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-pgsql-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-process-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-pspell-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-recode-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-snmp-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-soap-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-xml-5.4.16-36.3.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-xmlrpc-5.4.16-36.3.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
