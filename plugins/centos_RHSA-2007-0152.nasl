#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0152 and 
# CentOS Errata and Security Advisory 2007:0152 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25007);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2006-4226");
  script_bugtraq_id(19559);
  script_osvdb_id(28012);
  script_xref(name:"RHSA", value:"2007:0152");

  script_name(english:"CentOS 4 : mysql (CESA-2007:0152)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix a security flaw are now available for
Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries.

A flaw was found in the way MySQL handled case sensitive database
names. A user with the ability to create databases could gain
unauthorized access to other databases hosted by the MySQL server.
(CVE-2006-4226)

This flaw does not affect the version of MySQL distributed with Red
Hat Enterprise Linux 2.1, 3, or 5.

All users of the MySQL server are advised to upgrade to these updated
packages, which contain a backported patch which fixes this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-April/013646.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d581377c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-April/013654.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8de0ac7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-April/013655.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07c53043"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"mysql-4.1.20-2.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mysql-bench-4.1.20-2.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mysql-devel-4.1.20-2.RHEL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mysql-server-4.1.20-2.RHEL4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
