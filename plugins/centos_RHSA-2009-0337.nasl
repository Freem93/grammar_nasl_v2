#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0337 and 
# CentOS Errata and Security Advisory 2009:0337 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(36089);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-3658", "CVE-2008-3660", "CVE-2008-5498", "CVE-2008-5557", "CVE-2009-0754");
  script_bugtraq_id(30649, 31612, 32948, 33002, 33542);
  script_osvdb_id(47798);
  script_xref(name:"RHSA", value:"2009:0337");

  script_name(english:"CentOS 3 / 4 : php (CESA-2009:0337)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix several security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

A heap-based buffer overflow flaw was found in PHP's mbstring
extension. A remote attacker able to pass arbitrary input to a PHP
script using mbstring conversion functions could cause the PHP
interpreter to crash or, possibly, execute arbitrary code.
(CVE-2008-5557)

A flaw was found in the handling of the 'mbstring.func_overload'
configuration setting. A value set for one virtual host, or in a
user's .htaccess file, was incorrectly applied to other virtual hosts
on the same server, causing the handling of multibyte character
strings to not work correctly. (CVE-2009-0754)

A buffer overflow flaw was found in PHP's imageloadfont function. If a
PHP script allowed a remote attacker to load a carefully crafted font
file, it could cause the PHP interpreter to crash or, possibly,
execute arbitrary code. (CVE-2008-3658)

A flaw was found in the way PHP handled certain file extensions when
running in FastCGI mode. If the PHP interpreter was being executed via
FastCGI, a remote attacker could create a request which would cause
the PHP interpreter to crash. (CVE-2008-3660)

A memory disclosure flaw was found in the PHP gd extension's
imagerotate function. A remote attacker able to pass arbitrary values
as the 'background color' argument of the function could, possibly,
view portions of the PHP interpreter's memory. (CVE-2008-5498)

All php users are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues. The httpd web
server must be restarted for the changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015718.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa9f81d4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015719.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c3d7ed4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015722.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b2c648c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015723.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1dd7147"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015806.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33bdeda4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015807.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?249de006"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 134, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-domxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"php-4.3.2-51.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-devel-4.3.2-51.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-imap-4.3.2-51.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-ldap-4.3.2-51.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-mysql-4.3.2-51.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-odbc-4.3.2-51.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-pgsql-4.3.2-51.ent")) flag++;

if (rpm_check(release:"CentOS-4", reference:"php-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-devel-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-domxml-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-gd-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-imap-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ldap-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mbstring-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mysql-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ncurses-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-odbc-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pear-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pgsql-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-snmp-4.3.9-3.22.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-xmlrpc-4.3.9-3.22.15")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
