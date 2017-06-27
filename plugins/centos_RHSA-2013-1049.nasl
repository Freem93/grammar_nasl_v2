#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1049 and 
# CentOS Errata and Security Advisory 2013:1049 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68858);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/20 13:54:06 $");

  script_cve_id("CVE-2013-4113");
  script_osvdb_id(95152);
  script_xref(name:"RHSA", value:"2013:1049");

  script_name(english:"CentOS 5 / 6 : php (CESA-2013:1049)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix one security issue are now available for
Red Hat Enterprise Linux 5 and 6.

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
  # http://lists.centos.org/pipermail/centos-announce/2013-July/019850.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db315b17"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-July/019852.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71c64934"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ncurses");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"php-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-bcmath-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-cli-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-common-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-dba-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-devel-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-gd-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-imap-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-ldap-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-mbstring-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-mysql-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-ncurses-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-odbc-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-pdo-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-pgsql-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-snmp-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-soap-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-xml-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-xmlrpc-5.1.6-40.el5_9")) flag++;

if (rpm_check(release:"CentOS-6", reference:"php-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-bcmath-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-cli-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-common-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-dba-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-devel-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-embedded-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-enchant-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-fpm-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-gd-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-imap-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-intl-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-ldap-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mbstring-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mysql-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-odbc-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pdo-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pgsql-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-process-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pspell-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-recode-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-snmp-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-soap-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-tidy-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xml-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xmlrpc-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-zts-5.3.3-23.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
