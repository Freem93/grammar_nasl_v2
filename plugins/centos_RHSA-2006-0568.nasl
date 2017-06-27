#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0568 and 
# CentOS Errata and Security Advisory 2006:0568 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22037);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2006-1494", "CVE-2006-1990", "CVE-2006-3017");
  script_osvdb_id(24486, 24946, 25255);
  script_xref(name:"RHSA", value:"2006:0568");

  script_name(english:"CentOS 3 / 4 : php (CESA-2006:0568)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PHP packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

A directory traversal vulnerability was found in PHP. Local users
could bypass open_basedir restrictions allowing remote attackers to
create files in arbitrary directories via the tempnam() function.
(CVE-2006-1494)

The wordwrap() PHP function did not properly check for integer
overflow in the handling of the 'break' parameter. An attacker who
could control the string passed to the 'break' parameter could cause a
heap overflow. (CVE-2006-1990)

A flaw was found in the zend_hash_del() PHP function. For PHP scripts
that rely on the use of the unset() function, a remote attacker could
force variable initialization to be bypassed. This would be a security
issue particularly for installations that enable the
'register_globals' setting. 'register_globals' is disabled by default
in Red Hat Enterprise Linux. (CVE-2006-3017)

Users of PHP should upgrade to these updated packages, which contain
backported patches that resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b365787"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013006.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e548fdd7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013012.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?acf396e3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013013.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c67bf109"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013020.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?423b3632"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013021.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85b33839"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"php-4.3.2-33.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-devel-4.3.2-33.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-imap-4.3.2-33.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-ldap-4.3.2-33.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-mysql-4.3.2-33.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-odbc-4.3.2-33.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-pgsql-4.3.2-33.ent")) flag++;

if (rpm_check(release:"CentOS-4", reference:"php-4.3.9-3.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-devel-4.3.9-3.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-domxml-4.3.9-3.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-gd-4.3.9-3.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-imap-4.3.9-3.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ldap-4.3.9-3.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mbstring-4.3.9-3.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mysql-4.3.9-3.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ncurses-4.3.9-3.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-odbc-4.3.9-3.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pear-4.3.9-3.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pgsql-4.3.9-3.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-snmp-4.3.9-3.15")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-xmlrpc-4.3.9-3.15")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
