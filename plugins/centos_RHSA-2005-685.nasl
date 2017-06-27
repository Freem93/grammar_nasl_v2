#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:685 and 
# CentOS Errata and Security Advisory 2005:685 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67032);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/29 00:08:47 $");

  script_cve_id("CVE-2005-1636");
  script_osvdb_id(16689);
  script_xref(name:"RHSA", value:"2005:685");

  script_name(english:"CentOS 4 : mysql (CESA-2005:685)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix a temporary file flaw and a number of
bugs are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries.

An insecure temporary file handling bug was found in the
mysql_install_db script. It is possible for a local user to create
specially crafted files in /tmp which could allow them to execute
arbitrary SQL commands during database installation. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-1636 to this issue.

These packages update mysql to version 4.1.12, fixing a number of
problems. Also, support for SSL-encrypted connections to the database
server is now provided.

All users of mysql are advised to upgrade to these updated packages."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012242.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4ee6396"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"mysql-4.1.12-3.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"mysql-bench-4.1.12-3.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"mysql-devel-4.1.12-3.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"mysql-server-4.1.12-3.RHEL4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
