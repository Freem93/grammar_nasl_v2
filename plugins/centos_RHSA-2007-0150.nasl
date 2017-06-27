#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0150 and 
# CentOS Errata and Security Advisory 2007:0150 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25042);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:34:16 $");

  script_cve_id("CVE-2007-1351");
  script_bugtraq_id(23283);
  script_osvdb_id(34917, 34918);
  script_xref(name:"RHSA", value:"2007:0150");

  script_name(english:"CentOS 3 / 4 / 5 : freetype (CESA-2007:0150)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freetype packages that fix a security flaw are now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

FreeType is a free, high-quality, portable font engine.

An integer overflow flaw was found in the way the FreeType font engine
processed BDF font files. If a user loaded a carefully crafted font
file with a program linked against FreeType, it could cause the
application to crash or execute arbitrary code. While it is uncommon
for a user to explicitly load a font file, there are several
application file formats which contain embedded fonts that are parsed
by FreeType. (CVE-2007-1351)

This flaw did not affect the version of FreeType shipped in Red Hat
Enterprise Linux 2.1.

Users of FreeType should upgrade to these updated packages, which
contain a backported patch to correct this issue.

Red Hat would like to thank iDefense for reporting this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-April/013665.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db7ea549"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-April/013666.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6004880"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-April/013668.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e4e518d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-April/013671.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6939a5bc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-April/013684.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?135eaf33"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-April/013685.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1775dc2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-April/013688.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70f5e1ed"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-April/013689.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?423c20bd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"freetype-2.1.4-6.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"freetype-demos-2.1.4-6.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"freetype-devel-2.1.4-6.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"freetype-utils-2.1.4-6.el3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"freetype-2.1.9-5.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"freetype-demos-2.1.9-5.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"freetype-devel-2.1.9-5.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"freetype-utils-2.1.9-5.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"freetype-2.2.1-17.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freetype-demos-2.2.1-17.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freetype-devel-2.2.1-17.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
