#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1615 and 
# CentOS Errata and Security Advisory 2013:1615 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(79167);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/12 17:31:56 $");

  script_cve_id("CVE-2006-7243", "CVE-2013-1643", "CVE-2013-4248");
  script_bugtraq_id(44951, 58224, 61776);
  script_osvdb_id(70606, 90922, 96298);
  script_xref(name:"RHSA", value:"2013:1615");

  script_name(english:"CentOS 6 : php (CESA-2013:1615)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix three security issues, several bugs, and
add one enhancement are now available for Red Hat Enterprise Linux 6.

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

A flaw was found in PHP's SSL client's hostname identity check when
handling certificates that contain hostnames with NULL bytes. If an
attacker was able to get a carefully crafted certificate signed by a
trusted Certificate Authority, the attacker could use the certificate
to conduct man-in-the-middle attacks to spoof SSL servers.
(CVE-2013-4248)

It was found that the PHP SOAP parser allowed the expansion of
external XML entities during SOAP message parsing. A remote attacker
could possibly use this flaw to read arbitrary files that are
accessible to a PHP application using a SOAP extension.
(CVE-2013-1643)

This update fixes the following bugs :

* Previously, when the allow_call_time_pass_reference setting was
disabled, a virtual host on the Apache server could terminate with a
segmentation fault when attempting to process certain PHP content.
This bug has been fixed and virtual hosts no longer crash when
allow_call_time_pass_reference is off. (BZ#892158, BZ#910466)

* Prior to this update, if an error occurred during the operation of
the fclose(), file_put_contents(), or copy() function, the function
did not report it. This could have led to data loss. With this update,
the aforementioned functions have been modified to properly report any
errors. (BZ#947429)

* The internal buffer for the SQLSTATE error code can store maximum of
5 characters. Previously, when certain calls exceeded this limit, a
buffer overflow occurred. With this update, messages longer than 5
characters are automatically replaced with the default 'HY000' string,
thus preventing the overflow. (BZ#969110)

In addition, this update adds the following enhancement :

* This update adds the following rpm macros to the php package:
%__php, %php_inidir, %php_incldir. (BZ#953814)

Users of php are advised to upgrade to these updated packages, which
fix these bugs and add this enhancement. After installing the updated
packages, the httpd daemon must be restarted for the update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/001046.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?636970a5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
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
if (rpm_check(release:"CentOS-6", reference:"php-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-bcmath-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-cli-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-common-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-dba-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-devel-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-embedded-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-enchant-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-fpm-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-gd-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-imap-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-intl-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-ldap-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mbstring-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-mysql-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-odbc-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pdo-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pgsql-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-process-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-pspell-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-recode-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-snmp-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-soap-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-tidy-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xml-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-xmlrpc-5.3.3-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"php-zts-5.3.3-26.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
