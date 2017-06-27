#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0875 and 
# CentOS Errata and Security Advisory 2007:0875 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25958);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2007-3780");
  script_bugtraq_id(25017);
  script_osvdb_id(36732);
  script_xref(name:"RHSA", value:"2007:0875");

  script_name(english:"CentOS 4 / 5 : mysql (CESA-2007:0875)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix a security flaw are now available for
Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries.

A flaw was discovered in MySQL's authentication protocol. It is
possible for a remote unauthenticated attacker to send a specially
crafted authentication request to the MySQL server causing it to
crash. (CVE-2007-3780)

All users of the MySQL server are advised to upgrade to these updated
packages, which contain a backported patch which fixes this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-August/014155.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a56f0fa1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-August/014156.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45795d3a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-August/014157.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?978fa496"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014159.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d730211d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014160.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?01993c3b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/08");
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
if (rpm_check(release:"CentOS-4", reference:"mysql-4.1.20-2.RHEL4.1.0.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mysql-bench-4.1.20-2.RHEL4.1.0.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mysql-devel-4.1.20-2.RHEL4.1.0.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mysql-server-4.1.20-2.RHEL4.1.0.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"mysql-5.0.22-2.1.0.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-bench-5.0.22-2.1.0.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-devel-5.0.22-2.1.0.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-server-5.0.22-2.1.0.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-test-5.0.22-2.1.0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
