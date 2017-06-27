#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0029 and 
# CentOS Errata and Security Advisory 2008:0029 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(30022);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-4568", "CVE-2007-4990", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429", "CVE-2008-0006");
  script_bugtraq_id(25898, 27350, 27351, 27352, 27353, 27355, 27356);
  script_osvdb_id(37722, 40943);
  script_xref(name:"RHSA", value:"2008:0029");

  script_name(english:"CentOS 3 : XFree86 (CESA-2008:0029)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated XFree86 packages that fix several security issues are now
available for Red Hat Enterprise Linux 2.1 and 3.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

[Updated 18th January 2008] The original packages distributed with
this errata had a bug which could cause some X applications to fail on
32-bit platforms. We have updated the packages to correct this bug.

XFree86 is an implementation of the X Window System, which provides
the core functionality for the Linux graphical desktop.

Two integer overflow flaws were found in the XFree86 server's EVI and
MIT-SHM modules. A malicious authorized client could exploit these
issues to cause a denial of service (crash), or potentially execute
arbitrary code with root privileges on the XFree86 server.
(CVE-2007-6429)

A heap based buffer overflow flaw was found in the way the XFree86
server handled malformed font files. A malicious local user could
exploit this issue to potentially execute arbitrary code with the
privileges of the XFree86 server. (CVE-2008-0006)

A memory corruption flaw was found in the XFree86 server's XInput
extension. A malicious authorized client could exploit this issue to
cause a denial of service (crash), or potentially execute arbitrary
code with root privileges on the XFree86 server. (CVE-2007-6427)

An information disclosure flaw was found in the XFree86 server's
TOG-CUP extension. A malicious authorized client could exploit this
issue to cause a denial of service (crash), or potentially view
arbitrary memory content within the XFree86 server's address space.
(CVE-2007-6428)

An integer and heap overflow flaw were found in the X.org font server,
xfs. A user with the ability to connect to the font server could have
been able to cause a denial of service (crash), or potentially execute
arbitrary code with the permissions of the font server.
(CVE-2007-4568, CVE-2007-4990)

A flaw was found in the XFree86 server's XC-SECURITY extension, that
could have allowed a local user to verify the existence of an
arbitrary file, even in directories that are not normally accessible
to that user. (CVE-2007-5958)

Users of XFree86 are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014633.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?acd505b7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014634.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c24452b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014641.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eab2e5d0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xfree86 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 189, 200, 362, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"XFree86-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-100dpi-fonts-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-75dpi-fonts-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-14-100dpi-fonts-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-14-75dpi-fonts-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-15-100dpi-fonts-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-15-75dpi-fonts-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-2-100dpi-fonts-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-2-75dpi-fonts-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-9-100dpi-fonts-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-9-75dpi-fonts-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-Mesa-libGL-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-Mesa-libGLU-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-Xnest-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-Xvfb-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-base-fonts-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-cyrillic-fonts-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-devel-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-doc-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-font-utils-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-libs-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-libs-data-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-sdk-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-syriac-fonts-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-tools-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-truetype-fonts-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-twm-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-xauth-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-xdm-4.3.0-126.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-xfs-4.3.0-126.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
