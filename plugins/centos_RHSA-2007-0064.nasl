#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0064 and 
# CentOS Errata and Security Advisory 2007:0064 respectively.
#

include("compat.inc");

if (description)
{
  script_id(24290);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-5540", "CVE-2007-0555");
  script_bugtraq_id(22387);
  script_osvdb_id(30018, 33087);
  script_xref(name:"RHSA", value:"2007:0064");

  script_name(english:"CentOS 3 / 4 : postgresql (CESA-2007:0064)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix two security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PostgreSQL is an advanced Object-Relational database management system
(DBMS).

A flaw was found in the way the PostgreSQL server handles certain
SQL-language functions. An authenticated user could execute a sequence
of commands which could crash the PostgreSQL server or possibly read
from arbitrary memory locations. A user would need to have permissions
to drop and add database tables to be able to exploit this issue
(CVE-2007-0555).

A denial of service flaw was found affecting the PostgreSQL server
running on Red Hat Enterprise Linux 4 systems. An authenticated user
could execute a SQL command which could crash the PostgreSQL server.
(CVE-2006-5540)

Users of PostgreSQL should upgrade to these updated packages
containing PostgreSQL version 7.4.16 or 7.3.18, which correct these
issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013509.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6083066"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013510.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e835bcfc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013512.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f7e636d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013514.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10351f8f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013519.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d1d16f3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013520.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c9ebec8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rh-postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/09");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-7.3.18-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-contrib-7.3.18-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-devel-7.3.18-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-docs-7.3.18-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-jdbc-7.3.18-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-libs-7.3.18-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-pl-7.3.18-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-python-7.3.18-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-server-7.3.18-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-tcl-7.3.18-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-test-7.3.18-1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"postgresql-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-contrib-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-devel-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-docs-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-jdbc-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-libs-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-pl-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-python-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-server-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-tcl-7.4.16-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-test-7.4.16-1.RHEL4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
