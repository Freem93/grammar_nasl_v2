#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0713 and 
# CentOS Errata and Security Advisory 2006:0713 respectively.
#

include("compat.inc");

if (description)
{
  script_id(22514);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-4980");
  script_osvdb_id(29366);
  script_xref(name:"RHSA", value:"2006:0713");

  script_name(english:"CentOS 3 / 4 : python (CESA-2006:0713)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Python packages are now available to correct a security issue
in Red Hat Enterprise Linux 3 and 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Python is an interpreted, interactive, object-oriented programming
language.

A flaw was discovered in the way that the Python repr() function
handled UTF-32/UCS-4 strings. If an application written in Python used
the repr() function on untrusted data, this could lead to a denial of
service or possibly allow the execution of arbitrary code with the
privileges of the Python application. (CVE-2006-4980)

In addition, this errata fixes a regression in the SimpleXMLRPCServer
backport for Red Hat Enterprise Linux 3 that was introduced with
RHSA-2005:109.

Users of Python should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-October/013317.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58fa81dc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-October/013318.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0593b85"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-October/013319.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d88f5f3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-October/013321.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?130efa2d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-October/013323.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b80cc80"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-October/013324.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4daf892"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/16");
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
if (rpm_check(release:"CentOS-3", reference:"python-2.2.3-6.5")) flag++;
if (rpm_check(release:"CentOS-3", reference:"python-devel-2.2.3-6.5")) flag++;
if (rpm_check(release:"CentOS-3", reference:"python-docs-2.2.3-6.5")) flag++;
if (rpm_check(release:"CentOS-3", reference:"python-tools-2.2.3-6.5")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tkinter-2.2.3-6.5")) flag++;

if (rpm_check(release:"CentOS-4", reference:"python-2.3.4-14.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"python-devel-2.3.4-14.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"python-docs-2.3.4-14.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"python-tools-2.3.4-14.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tkinter-2.3.4-14.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
