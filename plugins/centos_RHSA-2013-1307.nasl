#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1307 and 
# CentOS Errata and Security Advisory 2013:1307 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(79149);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/12 17:31:56 $");

  script_cve_id("CVE-2006-7243", "CVE-2011-1398", "CVE-2012-0831", "CVE-2012-2688", "CVE-2013-1643", "CVE-2013-4248");
  script_bugtraq_id(44951, 51954, 55297, 58766, 61776);
  script_osvdb_id(70606, 79017, 84126, 85086, 90922, 96298);
  script_xref(name:"RHSA", value:"2013:1307");

  script_name(english:"CentOS 5 : php53 (CESA-2013:1307)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php53 packages that fix multiple security issues, several
bugs, and add one enhancement are now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

It was found that PHP did not properly handle file names with a NULL
character. A remote attacker could possibly use this flaw to make a
PHP script access unexpected files and bypass intended file system
access restrictions. (CVE-2006-7243)

It was found that PHP did not check for carriage returns in HTTP
headers, allowing intended HTTP response splitting protections to be
bypassed. Depending on the web browser the victim is using, a remote
attacker could use this flaw to perform HTTP response splitting
attacks. (CVE-2011-1398)

A flaw was found in PHP's SSL client's hostname identity check when
handling certificates that contain hostnames with NULL bytes. If an
attacker was able to get a carefully crafted certificate signed by a
trusted Certificate Authority, the attacker could use the certificate
to conduct man-in-the-middle attacks to spoof SSL servers.
(CVE-2013-4248)

An integer signedness issue, leading to a heap-based buffer underflow,
was found in the PHP scandir() function. If a remote attacker could
upload an excessively large number of files to a directory the
scandir() function runs on, it could cause the PHP interpreter to
crash or, possibly, execute arbitrary code. (CVE-2012-2688)

It was found that PHP did not correctly handle the magic_quotes_gpc
configuration directive. This could result in magic_quotes_gpc input
escaping not being applied in all cases, possibly making it easier for
a remote attacker to perform SQL injection attacks. (CVE-2012-0831)

It was found that the PHP SOAP parser allowed the expansion of
external XML entities during SOAP message parsing. A remote attacker
could possibly use this flaw to read arbitrary files that are
accessible to a PHP application using a SOAP extension.
(CVE-2013-1643)

These updated php53 packages also include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 5.10
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All PHP users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add this
enhancement. After installing the updated packages, the httpd daemon
must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-October/000863.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a75479b1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php53 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
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
if (rpm_check(release:"CentOS-5", reference:"php53-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-bcmath-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-cli-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-common-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-dba-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-devel-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-gd-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-imap-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-intl-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-ldap-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-mbstring-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-mysql-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-odbc-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pdo-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pgsql-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-process-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-pspell-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-snmp-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-soap-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-xml-5.3.3-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php53-xmlrpc-5.3.3-21.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
