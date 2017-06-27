#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:671 and 
# CentOS Errata and Security Advisory 2005:671 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21956);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-2097");
  script_xref(name:"RHSA", value:"2005:671");

  script_name(english:"CentOS 4 : kdegraphics (CESA-2005:671)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdegraphics packages that resolve a security issue in kpdf are
now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The kdegraphics packages contain applications for the K Desktop
Environment including kpdf, a pdf file viewer.

A flaw was discovered in kpdf. An attacker could construct a carefully
crafted PDF file that would cause kpdf to consume all available disk
space in /tmp when opened. The Common Vulnerabilities and Exposures
project assigned the name CVE-2005-2097 to this issue.

Note this issue does not affect Red Hat Enterprise Linux 3 or 2.1.

Users of kpdf should upgrade to these updated packages, which contains
a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012018.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17595d19"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012041.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06cff992"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012042.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5609f48"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdegraphics packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdegraphics-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
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
if (rpm_check(release:"CentOS-4", reference:"kdegraphics-3.3.1-3.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kdegraphics-devel-3.3.1-3.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
