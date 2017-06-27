#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1180 and 
# CentOS Errata and Security Advisory 2012:1180 respectively.
#

include("compat.inc");

if (description)
{
  script_id(61599);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/16 19:09:25 $");

  script_cve_id("CVE-2011-2896", "CVE-2012-3403", "CVE-2012-3481");
  script_osvdb_id(74539, 84830, 84831);
  script_xref(name:"RHSA", value:"2012:1180");

  script_name(english:"CentOS 6 : gimp (CESA-2012:1180)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gimp packages that fix three security issues are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The GIMP (GNU Image Manipulation Program) is an image composition and
editing program.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the GIMP's GIF image format plug-in. An attacker could create
a specially crafted GIF image file that, when opened, could cause the
GIF plug-in to crash or, potentially, execute arbitrary code with the
privileges of the user running the GIMP. (CVE-2012-3481)

A heap-based buffer overflow flaw was found in the Lempel-Ziv-Welch
(LZW) decompression algorithm implementation used by the GIMP's GIF
image format plug-in. An attacker could create a specially crafted GIF
image file that, when opened, could cause the GIF plug-in to crash or,
potentially, execute arbitrary code with the privileges of the user
running the GIMP. (CVE-2011-2896)

A heap-based buffer overflow flaw was found in the GIMP's KiSS CEL
file format plug-in. An attacker could create a specially crafted KiSS
palette file that, when opened, could cause the CEL plug-in to crash
or, potentially, execute arbitrary code with the privileges of the
user running the GIMP. (CVE-2012-3403)

Red Hat would like to thank Matthias Weckbecker of the SUSE Security
Team for reporting the CVE-2012-3481 issue.

Users of the GIMP are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The GIMP
must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-August/018813.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e8c0e7ef"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gimp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-devel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/21");
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
if (rpm_check(release:"CentOS-6", reference:"gimp-2.6.9-4.el6_3.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gimp-devel-2.6.9-4.el6_3.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gimp-devel-tools-2.6.9-4.el6_3.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gimp-help-browser-2.6.9-4.el6_3.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gimp-libs-2.6.9-4.el6_3.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
