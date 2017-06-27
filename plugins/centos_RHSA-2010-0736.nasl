#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0736 and 
# CentOS Errata and Security Advisory 2010:0736 respectively.
#

include("compat.inc");

if (description)
{
  script_id(49715);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/16 19:03:49 $");

  script_cve_id("CVE-2010-2806", "CVE-2010-3054", "CVE-2010-3311");
  script_osvdb_id(70334);
  script_xref(name:"RHSA", value:"2010:0736");

  script_name(english:"CentOS 3 : freetype (CESA-2010:0736)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freetype packages that fix three security issues are now
available for Red Hat Enterprise Linux 3.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

FreeType is a free, high-quality, portable font engine that can open
and manage font files. It also loads, hints, and renders individual
glyphs efficiently. The freetype packages for Red Hat Enterprise Linux
3 provide both the FreeType 1 and FreeType 2 font engines.

It was discovered that the FreeType font rendering engine improperly
validated certain position values when processing input streams. If a
user loaded a specially crafted font file with an application linked
against FreeType, and the relevant font glyphs were subsequently
rendered with the X FreeType library (libXft), it could trigger a
heap-based buffer overflow in the libXft library, causing the
application to crash or, possibly, execute arbitrary code with the
privileges of the user running the application. (CVE-2010-3311)

An array index error was found in the way the FreeType font rendering
engine processed certain PostScript Type 42 font files. If a user
loaded a specially crafted font file with an application linked
against FreeType, it could cause the application to crash or,
possibly, execute arbitrary code with the privileges of the user
running the application. (CVE-2010-2806)

A stack overflow flaw was found in the way the FreeType font rendering
engine processed PostScript Type 1 font files that contain nested
Standard Encoding Accented Character (seac) calls. If a user loaded a
specially crafted font file with an application linked against
FreeType, it could cause the application to crash. (CVE-2010-3054)

Note: All of the issues in this erratum only affect the FreeType 2
font engine.

Users are advised to upgrade to these updated packages, which contain
backported patches to correct these issues. The X server must be
restarted (log out, then log back in) for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017037.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c873305"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017038.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c9a12580"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"freetype-2.1.4-18.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"freetype-2.1.4-18.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"freetype-demos-2.1.4-18.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"freetype-demos-2.1.4-18.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"freetype-devel-2.1.4-18.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"freetype-devel-2.1.4-18.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"freetype-utils-2.1.4-18.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"freetype-utils-2.1.4-18.el3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
