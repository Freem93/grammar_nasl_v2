#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0131 and 
# CentOS Errata and Security Advisory 2008:0131 respectively.
#

include("compat.inc");

if (description)
{
  script_id(31301);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:34:18 $");

  script_cve_id("CVE-2008-0554");
  script_xref(name:"RHSA", value:"2008:0131");

  script_name(english:"CentOS 3 / 4 : netpbm (CESA-2008:0131)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated netpbm packages that fix a security issue are now available
for Red Hat Enterprise Linux 2.1, 3, and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The netpbm package contains a library of functions for editing and
converting between various graphics file formats, including .pbm
(portable bitmaps), .pgm (portable graymaps), .pnm (portable anymaps),
.ppm (portable pixmaps) and others. The package includes no
interactive tools and is primarily used by other programs (eg CGI
scripts that manage website images).

An input validation flaw was discovered in the GIF-to-PNM converter
(giftopnm) shipped with the netpbm package. An attacker could create a
carefully crafted GIF file which could cause giftopnm to crash or
possibly execute arbitrary code as the user running giftopnm.
(CVE-2008-0554)

All users are advised to upgrade to these updated packages which
contain a backported patch which resolves this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014718.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5aebe727"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014719.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c87279fa"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014722.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?029b4a37"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014723.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8bf05866"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014734.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b98ebf04"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014735.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7465a54"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected netpbm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netpbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netpbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netpbm-progs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"netpbm-9.24-11.30.5")) flag++;
if (rpm_check(release:"CentOS-3", reference:"netpbm-devel-9.24-11.30.5")) flag++;
if (rpm_check(release:"CentOS-3", reference:"netpbm-progs-9.24-11.30.5")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"netpbm-10.25-2.EL4.6.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"netpbm-10.25-2.EL4.6.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"netpbm-10.25-2.EL4.6.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"netpbm-devel-10.25-2.EL4.6.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"netpbm-devel-10.25-2.EL4.6.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"netpbm-devel-10.25-2.EL4.6.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"netpbm-progs-10.25-2.EL4.6.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"netpbm-progs-10.25-2.EL4.6.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"netpbm-progs-10.25-2.EL4.6.el4_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
