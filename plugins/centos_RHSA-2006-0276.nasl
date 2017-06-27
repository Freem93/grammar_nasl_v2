#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0276 and 
# CentOS Errata and Security Advisory 2006:0276 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21897);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2003-1303", "CVE-2005-2933", "CVE-2005-3883", "CVE-2006-0208", "CVE-2006-0996", "CVE-2006-1490");
  script_bugtraq_id(15009);
  script_osvdb_id(19856, 21239, 22480, 24248, 24484);
  script_xref(name:"RHSA", value:"2006:0276");

  script_name(english:"CentOS 3 / 4 : php (CESA-2006:0276)");
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

The phpinfo() PHP function did not properly sanitize long strings. An
attacker could use this to perform cross-site scripting attacks
against sites that have publicly-available PHP scripts that call
phpinfo(). (CVE-2006-0996)

The html_entity_decode() PHP function was found to not be binary safe.
An attacker could use this flaw to disclose a certain part of the
memory. In order for this issue to be exploitable the target site
would need to have a PHP script which called the
'html_entity_decode()' function with untrusted input from the user and
displayed the result. (CVE-2006-1490)

The error handling output was found to not properly escape HTML output
in certain cases. An attacker could use this flaw to perform
cross-site scripting attacks against sites where both display_errors
and html_errors are enabled. (CVE-2006-0208)

An input validation error was found in the 'mb_send_mail()' function.
An attacker could use this flaw to inject arbitrary headers in a mail
sent via a script calling the 'mb_send_mail()' function where the 'To'
parameter can be controlled by the attacker. (CVE-2005-3883)

A buffer overflow flaw was discovered in uw-imap, the University of
Washington's IMAP Server. php-imap is compiled against the static
c-client libraries from imap and therefore needed to be recompiled
against the fixed version. This issue only affected Red Hat Enterprise
Linux 3. (CVE-2005-2933).

Users of PHP should upgrade to these updated packages, which contain
backported patches that resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012842.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5780704b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012843.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f91c08c3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012849.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7258c55d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012852.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?778b738c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012853.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f6807b0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/04");
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
if (rpm_check(release:"CentOS-3", reference:"php-4.3.2-30.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-devel-4.3.2-30.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-imap-4.3.2-30.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-ldap-4.3.2-30.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-mysql-4.3.2-30.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-odbc-4.3.2-30.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-pgsql-4.3.2-30.ent")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-devel-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-devel-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-domxml-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-domxml-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-gd-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-gd-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-imap-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-imap-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-ldap-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-ldap-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-mbstring-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-mbstring-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-mysql-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-mysql-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-ncurses-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-ncurses-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-odbc-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-odbc-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-pear-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-pear-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-pgsql-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-pgsql-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-snmp-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-snmp-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"php-xmlrpc-4.3.9-3.12")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"php-xmlrpc-4.3.9-3.12")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
