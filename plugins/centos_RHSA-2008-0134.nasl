#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0134 and 
# CentOS Errata and Security Advisory 2008:0134 respectively.
#

include("compat.inc");

if (description)
{
  script_id(31139);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-4772", "CVE-2007-5378", "CVE-2008-0553");
  script_bugtraq_id(27163, 27655);
  script_xref(name:"RHSA", value:"2008:0134");

  script_name(english:"CentOS 3 : tcltk (CESA-2008:0134)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tcltk packages that fix a security issue are now available for
Red Hat Enterprise Linux 2.1, and 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Tcl is a scripting language designed for embedding into other
applications and for use with Tk, a widget set.

An input validation flaw was discovered in Tk's GIF image handling. A
code-size value read from a GIF image was not properly validated
before being used, leading to a buffer overflow. A specially crafted
GIF file could use this to cause a crash or, potentially, execute code
with the privileges of the application using the Tk graphical toolkit.
(CVE-2008-0553)

A buffer overflow flaw was discovered in Tk's animated GIF image
handling. An animated GIF containing an initial image smaller than
subsequent images could cause a crash or, potentially, execute code
with the privileges of the application using the Tk library.
(CVE-2007-5378)

A flaw in the Tcl regular expression handling engine was discovered by
Will Drewry. This flaw, first discovered in the Tcl regular expression
engine used in the PostgreSQL database server, resulted in an infinite
loop when processing certain regular expressions. (CVE-2007-4772)

All users are advised to upgrade to these updated packages which
contain backported patches which resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014691.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5ff1da3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014706.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c9bae73f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014707.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5de35b5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tcltk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:expect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:expect-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:expectk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:itcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tcl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tcl-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tcllib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tclx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tk-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/25");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"expect-5.38.0-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"expect-5.38.0-92.8.c3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"expect-5.38.0-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"expect-devel-5.38.0-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"expect-devel-5.38.0-92.8.c3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"expect-devel-5.38.0-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"expectk-5.38.0-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"expectk-5.38.0-92.8.c3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"expectk-5.38.0-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"itcl-3.2-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"itcl-3.2-92.8.c3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"itcl-3.2-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"tcl-8.3.5-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"tcl-8.3.5-92.8.c3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"tcl-8.3.5-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"tcl-devel-8.3.5-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"tcl-devel-8.3.5-92.8.c3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"tcl-devel-8.3.5-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"tcl-html-8.3.5-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"tcl-html-8.3.5-92.8.c3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"tcl-html-8.3.5-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"tcllib-1.3-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"tcllib-1.3-92.8.c3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"tcllib-1.3-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"tclx-8.3-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"tclx-8.3-92.8.c3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"tclx-8.3-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"tix-8.1.4-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"tix-8.1.4-92.8.c3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"tix-8.1.4-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"tk-8.3.5-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"tk-8.3.5-92.8.c3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"tk-8.3.5-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"tk-devel-8.3.5-92.8")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"tk-devel-8.3.5-92.8.c3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"tk-devel-8.3.5-92.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
