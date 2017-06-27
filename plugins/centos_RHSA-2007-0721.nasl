#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0721 and 
# CentOS Errata and Security Advisory 2007:0721 respectively.
#

include("compat.inc");

if (description)
{
  script_id(38130);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2007-3388");
  script_bugtraq_id(25154);
  script_osvdb_id(39385);
  script_xref(name:"RHSA", value:"2007:0721");

  script_name(english:"CentOS 3 / 4 / 5 : qt (CESA-2007:0721)");
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

Several format string flaws were found in Qt error message handling.
If an application linked against Qt created an error message from
user-supplied data in a certain way, it could lead to a denial of
service or possibly allow the execution of arbitrary code.
(CVE-2007-3388)

Users of Qt should upgrade to these updated packages, which contain a
backported patch to correct these issues.

Red Hat would like to acknowledge Tim Brown of Portcullis Computer
Security and Dirk Mueller for these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-August/014123.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dae11362"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-August/014124.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d52af50f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014100.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee5f82be"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014101.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?814fcabe"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014102.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?012e830c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014103.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33c4c751"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014112.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ec7c49a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014113.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65e5ef74"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-MySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-ODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-PostgreSQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-devel-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (rpm_check(release:"CentOS-3", reference:"qt-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-MySQL-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-ODBC-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-PostgreSQL-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-config-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-designer-3.1.2-16.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-devel-3.1.2-16.RHEL3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"qt-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-MySQL-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-ODBC-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-PostgreSQL-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-config-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-designer-3.3.3-11.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-devel-3.3.3-11.RHEL4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"qt-3.3.6-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt-MySQL-3.3.6-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt-ODBC-3.3.6-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt-PostgreSQL-3.3.6-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt-config-3.3.6-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt-designer-3.3.6-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt-devel-3.3.6-21.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt-devel-docs-3.3.6-21.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
