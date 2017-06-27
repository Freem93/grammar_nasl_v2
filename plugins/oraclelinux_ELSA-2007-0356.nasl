#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0356 and 
# Oracle Linux Security Advisory ELSA-2007-0356 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67500);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 16:16:27 $");

  script_cve_id("CVE-2006-5793", "CVE-2007-2445");
  script_bugtraq_id(21078);
  script_osvdb_id(30398, 36196);
  script_xref(name:"RHSA", value:"2007:0356");

  script_name(english:"Oracle Linux 3 / 4 / 5 : libpng (ELSA-2007-0356)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0356 :

Updated libpng packages that fix security issues are now available for
Red Hat Enterprise Linux.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The libpng package contains a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.

A flaw was found in the handling of malformed images in libpng. An
attacker could create a carefully crafted PNG image file in such a way
that it could cause an application linked with libpng to crash when
the file was manipulated. (CVE-2007-2445)

A flaw was found in the sPLT chunk handling code in libpng. An
attacker could create a carefully crafted PNG image file in such a way
that it could cause an application linked with libpng to crash when
the file was opened. (CVE-2006-5793)

Users of libpng should update to these updated packages which contain
backported patches to correct these issues.

Red Hat would like to thank Glenn Randers-Pehrson, Mats Palmgren, and
Tavis Ormandy for supplying details and patches for these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-June/000213.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-May/000156.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-May/000157.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpng packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpng10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpng10-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libpng-1.2.2-27")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libpng-1.2.2-27")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libpng-devel-1.2.2-27")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libpng-devel-1.2.2-27")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libpng10-1.0.13-17")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libpng10-1.0.13-17")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"libpng10-devel-1.0.13-17")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"libpng10-devel-1.0.13-17")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"libpng-1.2.7-3.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"libpng-1.2.7-3.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"libpng-devel-1.2.7-3.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"libpng-devel-1.2.7-3.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"libpng10-1.0.16-3")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"libpng10-1.0.16-3")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"libpng10-devel-1.0.16-3")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"libpng10-devel-1.0.16-3")) flag++;

if (rpm_check(release:"EL5", reference:"libpng-1.2.10-7.0.2")) flag++;
if (rpm_check(release:"EL5", reference:"libpng-devel-1.2.10-7.0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng / libpng-devel / libpng10 / libpng10-devel");
}
