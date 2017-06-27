#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0467 and 
# CentOS Errata and Security Advisory 2012:0467 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(58665);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2012-1126", "CVE-2012-1127", "CVE-2012-1130", "CVE-2012-1131", "CVE-2012-1132", "CVE-2012-1134", "CVE-2012-1136", "CVE-2012-1137", "CVE-2012-1139", "CVE-2012-1140", "CVE-2012-1141", "CVE-2012-1142", "CVE-2012-1143", "CVE-2012-1144");
  script_bugtraq_id(52318);
  script_osvdb_id(79872, 79873, 79876, 79877, 79878, 79881, 79883, 79884, 79886, 79887, 79888, 79889, 79890, 79891);
  script_xref(name:"RHSA", value:"2012:0467");

  script_name(english:"CentOS 5 / 6 : freetype (CESA-2012:0467)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freetype packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

FreeType is a free, high-quality, portable font engine that can open
and manage font files. It also loads, hints, and renders individual
glyphs efficiently.

Multiple flaws were found in the way FreeType handled TrueType Font
(TTF), Glyph Bitmap Distribution Format (BDF), Windows .fnt and .fon,
and PostScript Type 1 fonts. If a specially crafted font file was
loaded by an application linked against FreeType, it could cause the
application to crash or, potentially, execute arbitrary code with the
privileges of the user running the application. (CVE-2012-1134,
CVE-2012-1136, CVE-2012-1142, CVE-2012-1144)

Multiple flaws were found in the way FreeType handled fonts in various
formats. If a specially crafted font file was loaded by an application
linked against FreeType, it could cause the application to crash.
(CVE-2012-1126, CVE-2012-1127, CVE-2012-1130, CVE-2012-1131,
CVE-2012-1132, CVE-2012-1137, CVE-2012-1139, CVE-2012-1140,
CVE-2012-1141, CVE-2012-1143)

Red Hat would like to thank Mateusz Jurczyk of the Google Security
Team for reporting these issues.

Users are advised to upgrade to these updated packages, which contain
a backported patch to correct these issues. The X server must be
restarted (log out, then log back in) for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-April/018559.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e98ba3b8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-April/018563.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12ed040f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"freetype-2.2.1-31.el5_8.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freetype-demos-2.2.1-31.el5_8.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freetype-devel-2.2.1-31.el5_8.1")) flag++;

if (rpm_check(release:"CentOS-6", reference:"freetype-2.3.11-6.el6_2.9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"freetype-demos-2.3.11-6.el6_2.9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"freetype-devel-2.3.11-6.el6_2.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
