#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:501 and 
# CentOS Errata and Security Advisory 2005:501 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21833);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-2495");
  script_xref(name:"RHSA", value:"2005:501");

  script_name(english:"CentOS 3 : XFree86 (CESA-2005:501)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated XFree86 packages that fix several integer overflows, various
bugs, and add ATI RN50/ES1000 support are now available for Red Hat
Enterprise Linux 3.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

XFree86 is an implementation of the X Window System, which provides
the core functionality for the Linux graphical desktop.

Several integer overflow bugs were found in the way XFree86 parses
pixmap images. It is possible for a user to gain elevated privileges
by loading a specially crafted pixmap image. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-2495 to this issue.

Additionally this update adds the following new features in this
release: - Support for ATI RN50/ES1000 chipsets has been added.

The following bugs were also fixed in this release: - A problem with
the X server's module loading system that led to cache incoherency on
the Itanium architecture.

  - The X server's PCI config space accesses caused
    contention with the kernel if accesses occurred while
    the kernel lock was held.

  - X font server (xfs) crashed when accessing Type 1 fonts
    via showfont.

  - A problem with the X transport library prevented X
    applications from starting if the hostname started with
    a digit.

  - An issue where refresh rates were being restricted to
    60Hz on some Intel i8xx systems

Users of XFree86 should upgrade to these updated packages, which
contain a backported patch and are not vulnerable to this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012169.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ad44142"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012170.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18790aed"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012171.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9dbdac4f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xfree86 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-ISO8859-14-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-ISO8859-14-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-ISO8859-15-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-ISO8859-15-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-ISO8859-2-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-ISO8859-2-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-ISO8859-9-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-ISO8859-9-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-Mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-Mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-base-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-cyrillic-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-libs-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-syriac-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-truetype-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-xauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
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
if (rpm_check(release:"CentOS-3", reference:"XFree86-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-100dpi-fonts-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-75dpi-fonts-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-14-100dpi-fonts-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-14-75dpi-fonts-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-15-100dpi-fonts-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-15-75dpi-fonts-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-2-100dpi-fonts-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-2-75dpi-fonts-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-9-100dpi-fonts-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-9-75dpi-fonts-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-Mesa-libGL-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-Mesa-libGLU-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-Xnest-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-Xvfb-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-base-fonts-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-cyrillic-fonts-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-devel-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-doc-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-font-utils-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-libs-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-libs-data-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-sdk-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-syriac-fonts-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-tools-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-truetype-fonts-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-twm-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-xauth-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-xdm-4.3.0-95.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-xfs-4.3.0-95.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
