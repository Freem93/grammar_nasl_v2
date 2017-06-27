#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0544 and 
# CentOS Errata and Security Advisory 2008:0544 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(33524);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2007-4782", "CVE-2007-5898", "CVE-2007-5899", "CVE-2008-2051", "CVE-2008-2107", "CVE-2008-2108");
  script_bugtraq_id(26403, 29009);
  script_xref(name:"RHSA", value:"2008:0544");

  script_name(english:"CentOS 3 / 5 : php (CESA-2008:0544)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PHP packages that fix several security issues are now
available for Red Hat Enterprise Linux 3 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

It was discovered that the PHP escapeshellcmd() function did not
properly escape multi-byte characters which are not valid in the
locale used by the script. This could allow an attacker to bypass
quoting restrictions imposed by escapeshellcmd() and execute arbitrary
commands if the PHP script was using certain locales. Scripts using
the default UTF-8 locale are not affected by this issue.
(CVE-2008-2051)

PHP functions htmlentities() and htmlspecialchars() did not properly
recognize partial multi-byte sequences. Certain sequences of bytes
could be passed through these functions without being correctly
HTML-escaped. Depending on the browser being used, an attacker could
use this flaw to conduct cross-site scripting attacks. (CVE-2007-5898)

A PHP script which used the transparent session ID configuration
option, or which used the output_add_rewrite_var() function, could
leak session identifiers to external websites. If a page included an
HTML form with an ACTION attribute referencing a non-local URL, the
user's session ID would be included in the form data passed to that
URL. (CVE-2007-5899)

It was discovered that PHP fnmatch() function did not restrict the
length of the string argument. An attacker could use this flaw to
crash the PHP interpreter where a script used fnmatch() on untrusted
input data. (CVE-2007-4782)

It was discovered that PHP did not properly seed its pseudo-random
number generator used by functions such as rand() and mt_rand(),
possibly allowing an attacker to easily predict the generated
pseudo-random values. (CVE-2008-2107, CVE-2008-2108)

Users of PHP should upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015126.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?753e7a88"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015128.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?987e1e48"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015129.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f97bebe8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015141.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbab6f23"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015142.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a77b2e73"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 189, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"php-4.3.2-48.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-devel-4.3.2-48.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-imap-4.3.2-48.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-ldap-4.3.2-48.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-mysql-4.3.2-48.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-odbc-4.3.2-48.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-pgsql-4.3.2-48.ent")) flag++;

if (rpm_check(release:"CentOS-5", reference:"php-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-bcmath-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-cli-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-common-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-dba-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-devel-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-gd-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-imap-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-ldap-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-mbstring-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-mysql-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-ncurses-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-odbc-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-pdo-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-pgsql-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-snmp-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-soap-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-xml-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-xmlrpc-5.1.6-20.el5_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
