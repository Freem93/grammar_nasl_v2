#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0271 and 
# CentOS Errata and Security Advisory 2006:0271 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21895);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-4744", "CVE-2006-1354");
  script_osvdb_id(19317, 19318, 19319, 19320, 19321, 19322, 24025);
  script_xref(name:"RHSA", value:"2006:0271");

  script_name(english:"CentOS 3 / 4 : freeradius (CESA-2006:0271)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freeradius packages that fix an authentication weakness are
now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

FreeRADIUS is a high-performance and highly configurable free RADIUS
server designed to allow centralized authentication and authorization
for a network.

A bug was found in the way FreeRADIUS authenticates users via the
MSCHAP V2 protocol. It is possible for a remote attacker to
authenticate as a victim by sending a malformed MSCHAP V2 login
request to the FreeRADIUS server. (CVE-2006-1354)

Please note that FreeRADIUS installations not using the MSCHAP V2
protocol for authentication are not vulnerable to this issue.

A bug was also found in the way FreeRADIUS logs SQL errors from the
sql_unixodbc module. It may be possible for an attacker to cause
FreeRADIUS to crash or execute arbitrary code if they are able to
manipulate the SQL database FreeRADIUS is connecting to.
(CVE-2005-4744)

Users of FreeRADIUS should update to these erratum packages, which
contain backported patches and are not vulnerable to these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012782.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b174aa1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012783.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?210a20fa"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012786.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f9f0e43"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012787.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b89c4d9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012790.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d413fc55"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012796.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?996101d4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freeradius packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/08");
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
if (rpm_check(release:"CentOS-3", reference:"freeradius-1.0.1-2.RHEL3.2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"freeradius-mysql-1.0.1-2.RHEL3.2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"freeradius-postgresql-1.0.1-2.RHEL3.2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"freeradius-unixODBC-1.0.1-2.RHEL3.2")) flag++;

if (rpm_check(release:"CentOS-4", reference:"freeradius-1.0.1-3.RHEL4.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"freeradius-mysql-1.0.1-3.RHEL4.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"freeradius-postgresql-1.0.1-3.RHEL4.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"freeradius-unixODBC-1.0.1-3.RHEL4.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
