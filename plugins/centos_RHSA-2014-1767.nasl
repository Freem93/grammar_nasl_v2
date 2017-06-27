#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1767 and 
# CentOS Errata and Security Advisory 2014:1767 respectively.
#

include("compat.inc");

if (description)
{
  script_id(78782);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/07/23 14:53:34 $");

  script_cve_id("CVE-2014-3668", "CVE-2014-3669", "CVE-2014-3670", "CVE-2014-3710");
  script_bugtraq_id(70611, 70665, 70666, 70807);
  script_osvdb_id(113421, 113422, 113423, 113614);
  script_xref(name:"RHSA", value:"2014:1767");

  script_name(english:"CentOS 6 / 7 : php (CESA-2014:1767)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

A buffer overflow flaw was found in the Exif extension. A specially
crafted JPEG or TIFF file could cause a PHP application using the
exif_thumbnail() function to crash or, possibly, execute arbitrary
code with the privileges of the user running that PHP application.
(CVE-2014-3670)

An integer overflow flaw was found in the way custom objects were
unserialized. Specially crafted input processed by the unserialize()
function could cause a PHP application to crash. (CVE-2014-3669)

An out-of-bounds read flaw was found in the way the File Information
(fileinfo) extension parsed Executable and Linkable Format (ELF)
files. A remote attacker could use this flaw to crash a PHP
application using fileinfo via a specially crafted ELF file.
(CVE-2014-3710)

An out of bounds read flaw was found in the way the xmlrpc extension
parsed dates in the ISO 8601 format. A specially crafted XML-RPC
request or response could possibly cause a PHP application to crash.
(CVE-2014-3668)

The CVE-2014-3710 issue was discovered by Francisco Alonso of Red Hat
Product Security.

All php users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-October/020723.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87b0e151"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-October/020726.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54c857bb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysqlnd");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"php-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-bcmath-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-cli-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-common-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-dba-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-devel-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-embedded-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-enchant-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-fpm-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-gd-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-imap-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-intl-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-ldap-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mbstring-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mysql-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-odbc-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pdo-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pgsql-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-process-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pspell-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-recode-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-snmp-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-soap-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-tidy-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xml-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xmlrpc-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-zts-5.3.3-40.el6_6")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-bcmath-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-cli-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-common-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-dba-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-devel-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-embedded-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-enchant-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-fpm-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-gd-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-intl-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-ldap-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-mbstring-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-mysql-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-mysqlnd-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-odbc-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-pdo-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-pgsql-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-process-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-pspell-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-recode-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-snmp-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-soap-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-xml-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-xmlrpc-5.4.16-23.el7_0.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
