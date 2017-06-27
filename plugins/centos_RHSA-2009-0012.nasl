#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0012 and 
# CentOS Errata and Security Advisory 2009:0012 respectively.
#

include("compat.inc");

if (description)
{
  script_id(35650);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2007-2721", "CVE-2008-3520");
  script_bugtraq_id(31470);
  script_xref(name:"RHSA", value:"2009:0012");

  script_name(english:"CentOS 4 : netpbm (CESA-2009:0012)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated netpbm packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The netpbm package contains a library of functions for editing and
converting between various graphics file formats, including .pbm
(portable bitmaps), .pgm (portable graymaps), .pnm (portable anymaps),
.ppm (portable pixmaps), and others.

An input validation flaw and multiple integer overflows were
discovered in the JasPer library providing support for JPEG-2000 image
format and used in the jpeg2ktopam and pamtojpeg2k converters. An
attacker could create a carefully-crafted JPEG file which could cause
jpeg2ktopam to crash or, possibly, execute arbitrary code as the user
running jpeg2ktopam. (CVE-2007-2721, CVE-2008-3520)

All users are advised to upgrade to these updated packages which
contain backported patches which resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015631.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a004f6a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015632.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?691d41f3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015637.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42791b33"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected netpbm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netpbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netpbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netpbm-progs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"netpbm-10.25-2.1.el4.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"netpbm-10.25-2.1.c4.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"netpbm-10.25-2.1.el4.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"netpbm-devel-10.25-2.1.el4.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"netpbm-devel-10.25-2.1.c4.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"netpbm-devel-10.25-2.1.el4.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"netpbm-progs-10.25-2.1.el4.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"netpbm-progs-10.25-2.1.c4.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"netpbm-progs-10.25-2.1.el4.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
