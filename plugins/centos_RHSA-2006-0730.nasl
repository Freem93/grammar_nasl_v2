#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0730 and 
# CentOS Errata and Security Advisory 2006:0730 respectively.
#

include("compat.inc");

if (description)
{
  script_id(37281);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-5465");
  script_bugtraq_id(20879);
  script_osvdb_id(30178, 30179);
  script_xref(name:"RHSA", value:"2006:0730");

  script_name(english:"CentOS 3 / 4 : php (CESA-2006:0730)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PHP packages that fix a security issue are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

The Hardened-PHP Project discovered an overflow in the PHP
htmlentities() and htmlspecialchars() routines. If a PHP script used
the vulnerable functions to parse UTF-8 data, a remote attacker
sending a carefully crafted request could trigger the overflow and
potentially execute arbitrary code as the 'apache' user.
(CVE-2006-5465)

Users of PHP should upgrade to these updated packages which contain a
backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013349.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2830f751"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013350.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e04e660"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013353.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d167abb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013354.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e76f3d7a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013389.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0e7d6a7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013390.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?533f9891"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"php-4.3.2-37.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-devel-4.3.2-37.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-imap-4.3.2-37.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-ldap-4.3.2-37.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-mysql-4.3.2-37.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-odbc-4.3.2-37.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-pgsql-4.3.2-37.ent")) flag++;

if (rpm_check(release:"CentOS-4", reference:"php-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-devel-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-domxml-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-gd-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-imap-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ldap-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mbstring-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mysql-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ncurses-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-odbc-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pear-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pgsql-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-snmp-4.3.9-3.22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-xmlrpc-4.3.9-3.22")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
