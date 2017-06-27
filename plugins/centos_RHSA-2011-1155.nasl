#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1155 and 
# CentOS Errata and Security Advisory 2011:1155 respectively.
#

include("compat.inc");

if (description)
{
  script_id(55840);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2011-2895");
  script_bugtraq_id(49124);
  script_osvdb_id(74927);
  script_xref(name:"RHSA", value:"2011:1155");

  script_name(english:"CentOS 4 : xorg-x11 (CESA-2011:1155)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xorg-x11 packages that fix one security issue are now
available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon. These xorg-x11 packages also
provide the X.Org libXfont runtime library.

A buffer overflow flaw was found in the way the libXfont library, used
by the X.Org server, handled malformed font files compressed using
UNIX compress. A malicious, local user could exploit this issue to
potentially execute arbitrary code with the privileges of the X.Org
server. (CVE-2011-2895)

Users of xorg-x11 should upgrade to these updated packages, which
contain a backported patch to resolve this issue. All running X.Org
server instances must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-August/017661.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85da3873"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-August/017662.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bffbc3b0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-Xdmx-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-Xdmx-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-Xnest-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-Xnest-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-Xvfb-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-Xvfb-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-devel-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-devel-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-doc-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-doc-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-font-utils-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-font-utils-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-libs-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-libs-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-sdk-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-sdk-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-tools-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-tools-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-twm-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-twm-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-xauth-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-xauth-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-xdm-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-xdm-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xorg-x11-xfs-6.8.2-1.EL.69")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xorg-x11-xfs-6.8.2-1.EL.69")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
