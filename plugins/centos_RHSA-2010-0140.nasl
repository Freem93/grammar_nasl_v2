#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0140 and 
# CentOS Errata and Security Advisory 2010:0140 respectively.
#

include("compat.inc");

if (description)
{
  script_id(45066);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:43:07 $");

  script_cve_id("CVE-2010-0421");
  script_osvdb_id(63090);
  script_xref(name:"RHSA", value:"2010:0140");

  script_name(english:"CentOS 3 / 4 / 5 : pango (CESA-2010:0140)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pango and evolution28-pango packages that fix one security
issue are now available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Pango is a library used for the layout and rendering of
internationalized text.

An input sanitization flaw, leading to an array index error, was found
in the way the Pango font rendering library synthesized the Glyph
Definition (GDEF) table from a font's character map and the Unicode
property database. If an attacker created a specially crafted font
file and tricked a local, unsuspecting user into loading the font file
in an application that uses the Pango font rendering library, it could
cause that application to crash. (CVE-2010-0421)

Users of pango and evolution28-pango are advised to upgrade to these
updated packages, which contain a backported patch to resolve this
issue. After installing this update, you must restart your system or
restart your X session for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016560.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61436960"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016561.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b373a628"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016566.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9b39c46"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016567.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d4ccc7d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016568.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf23624f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016569.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3ba301e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pango packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution28-pango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution28-pango-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pango-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/17");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"pango-1.2.5-10")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"pango-1.2.5-10")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"pango-devel-1.2.5-10")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"pango-devel-1.2.5-10")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"evolution28-pango-1.14.9-13.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"evolution28-pango-1.14.9-13.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"evolution28-pango-devel-1.14.9-13.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"evolution28-pango-devel-1.14.9-13.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"pango-1.6.0-16.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"pango-1.6.0-16.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"pango-devel-1.6.0-16.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"pango-devel-1.6.0-16.el4_8")) flag++;

if (rpm_check(release:"CentOS-5", reference:"pango-1.14.9-8.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pango-devel-1.14.9-8.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
