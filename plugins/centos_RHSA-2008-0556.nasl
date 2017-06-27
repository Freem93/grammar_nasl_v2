#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0556 and 
# CentOS Errata and Security Advisory 2008:0556 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(33229);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808");
  script_bugtraq_id(29637, 29639, 29640, 29641);
  script_xref(name:"RHSA", value:"2008:0556");

  script_name(english:"CentOS 3 / 4 / 5 : freetype (CESA-2008:0556)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freetype packages that fix various security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

[Updated 25th June 2008] The original packages for Red Hat Enterprise
Linux 3 and 4 distributed with this errata had a bug which prevented
freetype library from loading certain font files correctly. We have
updated the packages to correct this bug.

FreeType is a free, high-quality, portable font engine that can open
and manage font files, as well as efficiently load, hint and render
individual glyphs.

Multiple flaws were discovered in FreeType's Printer Font Binary (PFB)
font-file format parser. If a user loaded a carefully crafted
font-file with a program linked against FreeType, it could cause the
application to crash, or possibly execute arbitrary code.
(CVE-2008-1806, CVE-2008-1807, CVE-2008-1808)

Note: the flaw in FreeType's TrueType Font (TTF) font-file format
parser, covered by CVE-2008-1808, did not affect the freetype packages
as shipped in Red Hat Enterprise Linux 3, 4, and 5, as they are not
compiled with TTF Byte Code Interpreter (BCI) support.

Users of freetype should upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015000.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?856831a3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015001.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6058335b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015006.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?59599ecc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015007.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c030351"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015024.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?994e54e7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015025.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e8a3f317"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015052.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a353252c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015054.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06287a44"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/24");
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
if (rpm_check(release:"CentOS-3", reference:"freetype-2.1.4-10.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"freetype-demos-2.1.4-10.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"freetype-devel-2.1.4-10.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"freetype-utils-2.1.4-10.el3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"freetype-2.1.9-7.el4.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"freetype-2.1.9-8.el4.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"freetype-2.1.9-7.el4.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"freetype-demos-2.1.9-7.el4.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"freetype-demos-2.1.9-8.el4.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"freetype-demos-2.1.9-7.el4.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"freetype-devel-2.1.9-7.el4.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"freetype-devel-2.1.9-8.el4.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"freetype-devel-2.1.9-7.el4.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"freetype-utils-2.1.9-7.el4.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"freetype-utils-2.1.9-8.el4.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"freetype-utils-2.1.9-7.el4.6")) flag++;

if (rpm_check(release:"CentOS-5", reference:"freetype-2.2.1-20.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freetype-demos-2.2.1-20.el5_2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freetype-devel-2.2.1-20.el5_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
