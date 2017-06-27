#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:564 and 
# CentOS Errata and Security Advisory 2005:564 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21841);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/06/14 17:29:26 $");

  script_cve_id("CVE-2005-1751", "CVE-2005-1921");
  script_bugtraq_id(14088);
  script_osvdb_id(16848, 17793);
  script_xref(name:"RHSA", value:"2005:564");

  script_name(english:"CentOS 3 / 4 : php (CESA-2005:564)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PHP packages that fix two security issues are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

A bug was discovered in the PEAR XML-RPC Server package included in
PHP. If a PHP script is used which implements an XML-RPC Server using
the PEAR XML-RPC package, then it is possible for a remote attacker to
construct an XML-RPC request which can cause PHP to execute arbitrary
PHP commands as the 'apache' user. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-1921
to this issue.

When using the default SELinux 'targeted' policy on Red Hat Enterprise
Linux 4, the impact of this issue is reduced since the scripts
executed by PHP are constrained within the httpd_sys_script_t security
context.

A race condition in temporary file handling was discovered in the
shtool script installed by PHP. If a third-party PHP module which uses
shtool was compiled as root, a local user may be able to modify
arbitrary files. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1751 to this issue.

Users of PHP should upgrade to these updated packages, which contain
backported fixes for these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011918.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bde570a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011919.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eee79935"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011920.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?976c3a5f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011921.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b6ccf66"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011922.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a78813f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011923.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3836c6f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP XML-RPC Arbitrary Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"php-4.3.2-24.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-devel-4.3.2-24.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-imap-4.3.2-24.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-ldap-4.3.2-24.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-mysql-4.3.2-24.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-odbc-4.3.2-24.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-pgsql-4.3.2-24.ent")) flag++;

if (rpm_check(release:"CentOS-4", reference:"php-4.3.9-3.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-devel-4.3.9-3.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-domxml-4.3.9-3.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-gd-4.3.9-3.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-imap-4.3.9-3.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ldap-4.3.9-3.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mbstring-4.3.9-3.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mysql-4.3.9-3.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ncurses-4.3.9-3.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-odbc-4.3.9-3.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pear-4.3.9-3.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pgsql-4.3.9-3.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-snmp-4.3.9-3.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-xmlrpc-4.3.9-3.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
