#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0544 and 
# CentOS Errata and Security Advisory 2006:0544 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22000);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2006-0903", "CVE-2006-1516", "CVE-2006-1517", "CVE-2006-2753", "CVE-2006-3081", "CVE-2006-4380");
  script_bugtraq_id(17780);
  script_osvdb_id(23526, 25226, 25228, 25987);
  script_xref(name:"RHSA", value:"2006:0544");

  script_name(english:"CentOS 4 : mysql (CESA-2006:0544)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix multiple security flaws are now
available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries.

A flaw was found in the way the MySQL mysql_real_escape() function
escaped strings when operating in a multibyte character encoding. An
attacker could provide an application a carefully crafted string
containing invalidly-encoded characters which may be improperly
escaped, leading to the injection of malicious SQL commands.
(CVE-2006-2753)

An information disclosure flaw was found in the way the MySQL server
processed malformed usernames. An attacker could view a small portion
of server memory by supplying an anonymous login username which was
not null terminated. (CVE-2006-1516)

An information disclosure flaw was found in the way the MySQL server
executed the COM_TABLE_DUMP command. An authenticated malicious user
could send a specially crafted packet to the MySQL server which
returned random unallocated memory. (CVE-2006-1517)

A log file obfuscation flaw was found in the way the
mysql_real_query() function creates log file entries. An attacker with
the the ability to call the mysql_real_query() function against a
mysql server can obfuscate the entry the server will write to the log
file. However, an attacker needed to have complete control over a
server in order to attempt this attack. (CVE-2006-0903)

This update also fixes numerous non-security-related flaws, such as
intermittent authentication failures.

All users of mysql are advised to upgrade to these updated packages
containing MySQL version 4.1.20, which is not vulnerable to these
issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012951.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8801dec0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012952.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08e7baec"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012960.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?810595bb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/25");
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
if (rpm_check(release:"CentOS-4", reference:"mysql-4.1.20-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mysql-bench-4.1.20-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mysql-devel-4.1.20-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mysql-server-4.1.20-1.RHEL4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
