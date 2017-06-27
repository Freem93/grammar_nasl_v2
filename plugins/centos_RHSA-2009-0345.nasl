#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0345 and 
# CentOS Errata and Security Advisory 2009:0345 respectively.
#

include("compat.inc");

if (description)
{
  script_id(35966);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2009-0583", "CVE-2009-0584");
  script_osvdb_id(52988, 53255);
  script_xref(name:"RHSA", value:"2009:0345");

  script_name(english:"CentOS 3 / 4 : ghostscript (CESA-2009:0345)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ghostscript packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Ghostscript is a set of software that provides a PostScript(TM)
interpreter, a set of C procedures (the Ghostscript library, which
implements the graphics capabilities in the PostScript language) and
an interpreter for Portable Document Format (PDF) files.

Multiple integer overflow flaws which could lead to heap-based buffer
overflows, as well as multiple insufficient input validation flaws,
were found in Ghostscript's International Color Consortium Format
library (icclib). Using specially crafted ICC profiles, an attacker
could create a malicious PostScript or PDF file with embedded images
which could cause Ghostscript to crash, or, potentially, execute
arbitrary code when opened by the victim. (CVE-2009-0583,
CVE-2009-0584)

All users of ghostscript are advised to upgrade to these updated
packages, which contain a backported patch to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015810.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfa6e387"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015811.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f812b349"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-March/015688.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c556fcdb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-March/015689.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7784098"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-March/015696.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7370a342"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-March/015697.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18b8a850"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hpijs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/20");
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
if (rpm_check(release:"CentOS-3", reference:"ghostscript-7.05-32.1.17")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ghostscript-devel-7.05-32.1.17")) flag++;
if (rpm_check(release:"CentOS-3", reference:"hpijs-1.3-32.1.17")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ghostscript-7.07-33.2.el4_7.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ghostscript-7.07-33.2.c4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ghostscript-7.07-33.2.el4_7.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ghostscript-devel-7.07-33.2.el4_7.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ghostscript-devel-7.07-33.2.c4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ghostscript-devel-7.07-33.2.el4_7.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ghostscript-gtk-7.07-33.2.el4_7.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ghostscript-gtk-7.07-33.2.c4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ghostscript-gtk-7.07-33.2.el4_7.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
