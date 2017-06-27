#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1455 and 
# CentOS Errata and Security Advisory 2011:1455 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56878);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2011-3439");
  script_bugtraq_id(50643);
  script_osvdb_id(77014);
  script_xref(name:"RHSA", value:"2011:1455");

  script_name(english:"CentOS 4 / 5 : freetype (CESA-2011:1455)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freetype packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

FreeType is a free, high-quality, portable font engine that can open
and manage font files. It also loads, hints, and renders individual
glyphs efficiently. The freetype packages for Red Hat Enterprise Linux
4 provide both the FreeType 1 and FreeType 2 font engines. The
freetype packages for Red Hat Enterprise Linux 5 and 6 provide only
the FreeType 2 font engine.

Multiple input validation flaws were found in the way FreeType
processed CID-keyed fonts. If a specially crafted font file was loaded
by an application linked against FreeType, it could cause the
application to crash or, potentially, execute arbitrary code with the
privileges of the user running the application. (CVE-2011-3439)

Note: These issues only affected the FreeType 2 font engine.

Users are advised to upgrade to these updated packages, which contain
a backported patch to correct these issues. The X server must be
restarted (log out, then log back in) for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018205.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d40d0a36"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018206.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ccce360"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018215.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e28f719"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018216.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?62765c6b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/22");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"freetype-2.1.9-21.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"freetype-2.1.9-21.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"freetype-demos-2.1.9-21.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"freetype-demos-2.1.9-21.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"freetype-devel-2.1.9-21.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"freetype-devel-2.1.9-21.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"freetype-utils-2.1.9-21.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"freetype-utils-2.1.9-21.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"freetype-2.2.1-28.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freetype-demos-2.2.1-28.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freetype-devel-2.2.1-28.el5_7.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
