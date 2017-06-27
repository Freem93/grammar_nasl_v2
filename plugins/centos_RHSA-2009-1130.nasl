#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1130 and 
# CentOS Errata and Security Advisory 2009:1130 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43764);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2009-0945", "CVE-2009-1709");
  script_bugtraq_id(34924, 35334);
  script_xref(name:"RHSA", value:"2009:1130");

  script_name(english:"CentOS 5 : kdegraphics (CESA-2009:1130)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdegraphics packages that fix two security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

The kdegraphics packages contain applications for the K Desktop
Environment (KDE). Scalable Vector Graphics (SVG) is an XML-based
language to describe vector images. KSVG is a framework aimed at
implementing the latest W3C SVG specifications.

A use-after-free flaw was found in the KDE KSVG animation element
implementation. A remote attacker could create a specially crafted SVG
image, which once opened by an unsuspecting user, could cause a denial
of service (Konqueror crash) or, potentially, execute arbitrary code
with the privileges of the user running Konqueror. (CVE-2009-1709)

A NULL pointer dereference flaw was found in the KDE, KSVG SVGList
interface implementation. A remote attacker could create a specially
crafted SVG image, which once opened by an unsuspecting user, would
cause memory corruption, leading to a denial of service (Konqueror
crash). (CVE-2009-0945)

All users of kdegraphics should upgrade to these updated packages,
which contain backported patches to correct these issues. The desktop
must be restarted (log out, then log back in) for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-June/016009.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3a60db2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-June/016010.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34e37347"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdegraphics packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdegraphics-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"kdegraphics-3.5.4-13.el5_3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kdegraphics-devel-3.5.4-13.el5_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
