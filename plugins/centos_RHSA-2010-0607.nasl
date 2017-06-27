#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0607 and 
# CentOS Errata and Security Advisory 2010:0607 respectively.
#

include("compat.inc");

if (description)
{
  script_id(48269);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:43:07 $");

  script_cve_id("CVE-2010-1797");
  script_xref(name:"RHSA", value:"2010:0607");

  script_name(english:"CentOS 3 / 4 / 5 : freetype (CESA-2010:0607)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freetype packages that fix two security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

FreeType is a free, high-quality, portable font engine that can open
and manage font files. It also loads, hints, and renders individual
glyphs efficiently. The freetype packages for Red Hat Enterprise Linux
3 and 4 provide both the FreeType 1 and FreeType 2 font engines. The
freetype packages for Red Hat Enterprise Linux 5 provide only the
FreeType 2 font engine.

Two stack overflow flaws were found in the way the FreeType font
engine processed certain Compact Font Format (CFF) character strings
(opcodes). If a user loaded a specially crafted font file with an
application linked against FreeType, it could cause the application to
crash or, possibly, execute arbitrary code with the privileges of the
user running the application. (CVE-2010-1797)

Red Hat would like to thank Braden Thomas of the Apple Product
Security team for reporting these issues.

Note: CVE-2010-1797 only affects the FreeType 2 font engine.

Users are advised to upgrade to these updated packages, which contain
a backported patch to correct these issues. The X server must be
restarted (log out, then log back in) for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016872.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3821645"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016873.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb5847a5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016888.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d740387"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016889.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75c64d3c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016922.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6692d834"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016923.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6747a2d0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"freetype-2.1.4-16.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"freetype-2.1.4-16.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"freetype-demos-2.1.4-16.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"freetype-demos-2.1.4-16.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"freetype-devel-2.1.4-16.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"freetype-devel-2.1.4-16.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"freetype-utils-2.1.4-16.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"freetype-utils-2.1.4-16.el3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"freetype-2.1.9-15.el4.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"freetype-2.1.9-15.el4.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"freetype-demos-2.1.9-15.el4.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"freetype-demos-2.1.9-15.el4.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"freetype-devel-2.1.9-15.el4.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"freetype-devel-2.1.9-15.el4.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"freetype-utils-2.1.9-15.el4.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"freetype-utils-2.1.9-15.el4.8")) flag++;

if (rpm_check(release:"CentOS-5", reference:"freetype-2.2.1-26.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freetype-demos-2.2.1-26.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freetype-devel-2.2.1-26.el5_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
