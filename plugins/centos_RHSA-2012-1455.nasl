#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1455 and 
# CentOS Errata and Security Advisory 2012:1455 respectively.
#

include("compat.inc");

if (description)
{
  script_id(62910);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/16 19:09:25 $");

  script_cve_id("CVE-2012-4433");
  script_bugtraq_id(56404);
  script_osvdb_id(87147);
  script_xref(name:"RHSA", value:"2012:1455");

  script_name(english:"CentOS 6 : gegl (CESA-2012:1455)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gegl packages that fix one security issue are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

GEGL (Generic Graphics Library) is a graph-based image processing
framework.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way the gegl utility processed .ppm (Portable Pixel Map)
image files. An attacker could create a specially crafted .ppm file
that, when opened in gegl, would cause gegl to crash or, potentially,
execute arbitrary code. (CVE-2012-4433)

This issue was discovered by Murray McAllister of the Red Hat Security
Response Team.

Users of gegl should upgrade to these updated packages, which contain
a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-November/018991.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?440ef1dc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gegl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gegl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gegl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"gegl-0.1.2-4.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gegl-devel-0.1.2-4.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
