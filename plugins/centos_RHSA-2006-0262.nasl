#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0262 and 
# CentOS Errata and Security Advisory 2006:0262 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21989);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-3627", "CVE-2006-0746");
  script_bugtraq_id(16143);
  script_osvdb_id(23833);
  script_xref(name:"RHSA", value:"2006:0262");

  script_name(english:"CentOS 4 : kdegraphics (CESA-2006:0262)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdegraphics packages that fully resolve a security issue in
kpdf are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kdegraphics packages contain applications for the K Desktop
Environment including kpdf, a PDF file viewer.

Marcelo Ricardo Leitner discovered that a kpdf security fix,
CVE-2005-3627, was incomplete. Red Hat issued kdegraphics packages
with this incomplete fix in RHSA-2005:868. An attacker could construct
a carefully crafted PDF file that could cause kpdf to crash or
possibly execute arbitrary code when opened. The Common
Vulnerabilities and Exposures project assigned the name CVE-2006-0746
to this issue.

Users of kpdf should upgrade to these updated packages, which contain
a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012718.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71febce5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012726.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d64f2d6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012733.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b328e220"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdegraphics packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdegraphics-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/08");
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
if (rpm_check(release:"CentOS-4", reference:"kdegraphics-3.3.1-3.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kdegraphics-devel-3.3.1-3.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
