#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:433 and 
# CentOS Errata and Security Advisory 2005:433 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21826);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-1409", "CVE-2005-1410");
  script_osvdb_id(16323, 16324);
  script_xref(name:"RHSA", value:"2005:433");

  script_name(english:"CentOS 3 / 4 : postgresql (CESA-2005:433)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postgresql packages that fix several security vulnerabilities
and risks of data loss are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PostgreSQL is an advanced Object-Relational database management system
(DBMS) that supports almost all SQL constructs (including
transactions, subselects and user-defined types and functions).

The PostgreSQL community discovered two distinct errors in initial
system catalog entries that could allow authorized database users to
crash the database and possibly escalate their privileges. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
names CVE-2005-1409 and CVE-2005-1410 to these issues.

Although installing this update will protect new (freshly initdb'd)
database installations from these errors, administrators MUST TAKE
MANUAL ACTION to repair the errors in pre-existing databases. The
appropriate procedures are explained at
http://www.postgresql.org/docs/8.0/static/release-7-4-8.html for Red
Hat Enterprise Linux 4 users, or
http://www.postgresql.org/docs/8.0/static/release-7-3-10.html for Red
Hat Enterprise Linux 3 users.

This update corrects several problems that might occur while trying to
upgrade a Red Hat Enterprise Linux 3 installation (containing
rh-postgresql packages) to Red Hat Enterprise Linux 4 (containing
postgresql packages). These updated packages correctly supersede the
rh-postgresql packages.

The original release of Red Hat Enterprise Linux 4 failed to
initialize the database correctly if started for the first time with
SELinux in enforcement mode. This update corrects that problem.

If you already have a nonfunctional database in place, shut down the
postgresql service if running, install this update, then do 'sudo rm
-rf /var/lib/pgsql/data' before restarting the postgresql service.

This update also solves the problem that the PostgreSQL server might
fail to restart after a system reboot, due to a stale lockfile.

This update also corrects a problem with wrong error messages in
libpq, the postgresql client library. The library would formerly
report kernel error messages incorrectly when the locale setting was
not C.

This update also includes fixes for several other errors, including
two race conditions that could result in apparent data inconsistency
or actual data loss.

All users of PostgreSQL are advised to upgrade to these updated
packages and to apply the recommended manual corrections to existing
databases."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011771.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18303e72"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011772.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f4b0755"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011777.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0daaaad4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011778.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85b188c3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011784.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c185622"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011786.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a863fc4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
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
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-7.3.10-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-contrib-7.3.10-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-devel-7.3.10-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-docs-7.3.10-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-jdbc-7.3.10-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-libs-7.3.10-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-pl-7.3.10-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-python-7.3.10-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-server-7.3.10-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-tcl-7.3.10-1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"rh-postgresql-test-7.3.10-1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"postgresql-7.4.8-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-contrib-7.4.8-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-devel-7.4.8-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-docs-7.4.8-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-jdbc-7.4.8-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-libs-7.4.8-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-pl-7.4.8-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-python-7.4.8-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-server-7.4.8-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-tcl-7.4.8-1.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"postgresql-test-7.4.8-1.RHEL4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
