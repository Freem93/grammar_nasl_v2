#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:198 and 
# CentOS Errata and Security Advisory 2005:198 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21921);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-0605");
  script_osvdb_id(14373);
  script_xref(name:"RHSA", value:"2005:198");

  script_name(english:"CentOS 4 : xorg-x11 (CESA-2005:198)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xorg-x11 packages that fix a security issue as well as various
bugs are now available for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

X.Org X11 is the X Window System which provides the core functionality
of the Linux GUI desktop.

An integer overflow flaw was found in libXpm, which is used by some
applications for loading of XPM images. An attacker could create a
carefully crafted XPM file in such a way that it could cause an
application linked with libXpm to execute arbitrary code when the file
was opened by a victim. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-0605 to this
issue.

Since the initial release of Red Hat Enterprise Linux 4, a number of
issues have been addressed in the X.Org X11 X Window System. This
erratum also updates X11R6.8 to the latest stable point release
(6.8.2), which includes various stability and reliability fixes
including (but not limited to) the following :

  - The 'radeon' driver has been modified to disable
    'RENDER' acceleration by default, due to a bug in the
    implementation which has not yet been isolated. This can
    be manually re-enabled by using the following option in
    the device section of the X server config file :

Option 'RenderAccel'

  - The 'vmware' video driver is now available on 64-bit
    AMD64 and compatible systems.

  - The Intel 'i810' video driver is now available on 64-bit
    EM64T systems.

  - Stability fixes in the X Server's PCI handling layer for
    64-bit systems, which resolve some issues reported by
    'vesa' and 'nv' driver users.

  - Support for Hewlett Packard's Itanium ZX2 chipset.

  - Nvidia 'nv' video driver update provides support for
    some of the newer Nvidia chipsets, as well as many
    stability and reliability fixes.

  - Intel i810 video driver stability update, which fixes
    the widely reported i810/i815 screen refresh issues many
    have experienced.

  - Packaging fixes for multilib systems, which permit both
    32-bit and 64-bit X11 development environments to be
    simultaneously installed without file conflicts.

In addition to the above highlights, the X.Org X11 6.8.2 release has a
large number of additional stability fixes which resolve various other
issues reported since the initial release of Red Hat Enterprise Linux
4.

All users of X11 should upgrade to these updated packages, which
resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011797.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3c9dcde"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011806.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?556b1143"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011807.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10858b70"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fonts-xorg-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fonts-xorg-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fonts-xorg-ISO8859-14-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fonts-xorg-ISO8859-14-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fonts-xorg-ISO8859-15-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fonts-xorg-ISO8859-15-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fonts-xorg-ISO8859-2-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fonts-xorg-ISO8859-2-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fonts-xorg-ISO8859-9-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fonts-xorg-ISO8859-9-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fonts-xorg-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fonts-xorg-cyrillic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fonts-xorg-syriac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fonts-xorg-truetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-Mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-Mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-deprecated-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-deprecated-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-xauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/01");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"fonts-xorg-100dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"fonts-xorg-100dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"fonts-xorg-75dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"fonts-xorg-75dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"fonts-xorg-ISO8859-14-100dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"fonts-xorg-ISO8859-14-100dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"fonts-xorg-ISO8859-14-75dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"fonts-xorg-ISO8859-14-75dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"fonts-xorg-ISO8859-15-100dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"fonts-xorg-ISO8859-15-100dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"fonts-xorg-ISO8859-15-75dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"fonts-xorg-ISO8859-15-75dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"fonts-xorg-ISO8859-2-100dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"fonts-xorg-ISO8859-2-100dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"fonts-xorg-ISO8859-2-75dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"fonts-xorg-ISO8859-2-75dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"fonts-xorg-ISO8859-9-100dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"fonts-xorg-ISO8859-9-100dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"fonts-xorg-ISO8859-9-75dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"fonts-xorg-ISO8859-9-75dpi-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"fonts-xorg-base-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"fonts-xorg-base-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"fonts-xorg-cyrillic-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"fonts-xorg-cyrillic-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"fonts-xorg-syriac-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"fonts-xorg-syriac-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"fonts-xorg-truetype-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"fonts-xorg-truetype-6.8.1.1-1.EL.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-Xdmx-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-Xnest-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-Xvfb-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-devel-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-doc-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-font-utils-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-libs-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-sdk-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-tools-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-twm-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-xauth-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-xdm-6.8.2-1.EL.13.6")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-xfs-6.8.2-1.EL.13.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
