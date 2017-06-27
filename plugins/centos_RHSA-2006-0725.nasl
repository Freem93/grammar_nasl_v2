#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0725 and 
# CentOS Errata and Security Advisory 2006:0725 respectively.
#

include("compat.inc");

if (description)
{
  script_id(36520);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-4811");
  script_bugtraq_id(20599);
  script_osvdb_id(29843);
  script_xref(name:"RHSA", value:"2006:0725");

  script_name(english:"CentOS 3 / 4 : qt (CESA-2006:0725)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qt packages that correct an integer overflow flaw are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Qt is a software toolkit that simplifies the task of writing and
maintaining GUI (Graphical User Interface) applications for the X
Window System.

An integer overflow flaw was found in the way Qt handled certain
pixmap images. If an application linked against Qt created a pixmap
image in a certain way, it could lead to a denial of service or
possibly allow the execution of arbitrary code. (CVE-2006-4811)

Users of Qt should upgrade to these updated packages, which contain a
backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013339.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58113b3a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013340.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16366aff"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013341.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8bd4feef"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013342.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b60311d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013346.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6831eb7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013347.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37f12522"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-MySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-ODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-PostgreSQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/18");
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
if (rpm_check(release:"CentOS-3", reference:"qt-3.1.2-14.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-MySQL-3.1.2-14.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-ODBC-3.1.2-14.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-PostgreSQL-3.1.2-14.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-config-3.1.2-14.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-designer-3.1.2-14.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-devel-3.1.2-14.RHEL3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"qt-3.3.3-10.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-MySQL-3.3.3-10.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-ODBC-3.3.3-10.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"qt-PostgreSQL-3.3.3-10.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"qt-PostgreSQL-3.3.3-10.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-config-3.3.3-10.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-designer-3.3.3-10.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-devel-3.3.3-10.RHEL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
