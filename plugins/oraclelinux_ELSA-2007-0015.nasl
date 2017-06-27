#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0015 and 
# Oracle Linux Security Advisory ELSA-2007-0015 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67439);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:16:26 $");

  script_cve_id("CVE-2006-2440", "CVE-2006-5456", "CVE-2006-5868");
  script_bugtraq_id(20707);
  script_osvdb_id(27951, 28540, 29989, 29990);
  script_xref(name:"RHSA", value:"2007:0015");

  script_name(english:"Oracle Linux 3 / 4 : ImageMagick (ELSA-2007-0015)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0015 :

Updated ImageMagick packages that correct several security issues are
now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

ImageMagick is an image display and manipulation tool for the X Window
System that can read and write multiple image formats.

Several security flaws were discovered in the way ImageMagick decodes
DCM, PALM, and SGI graphic files. An attacker may be able to execute
arbitrary code on a victim's machine if they were able to trick the
victim into opening a specially crafted image file (CVE-2006-5456,
CVE-2006-5868).

A heap overflow flaw was found in ImageMagick. An attacker may be able
to execute arbitrary code on a victim's machine if they were able to
trick the victim into opening a specially crafted file
(CVE-2006-2440). This issue only affected the version of ImageMagick
distributed with Red Hat Enterprise Linux 4.

Users of ImageMagick should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-February/000050.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-March/000097.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected imagemagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/02");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"ImageMagick-5.5.6-24")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"ImageMagick-5.5.6-24")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"ImageMagick-c++-5.5.6-24")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"ImageMagick-c++-5.5.6-24")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"ImageMagick-c++-devel-5.5.6-24")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"ImageMagick-c++-devel-5.5.6-24")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"ImageMagick-devel-5.5.6-24")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"ImageMagick-devel-5.5.6-24")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"ImageMagick-perl-5.5.6-24")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"ImageMagick-perl-5.5.6-24")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"ImageMagick-6.0.7.1-16.0.3")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ImageMagick-6.0.7.1-16.0.3")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ImageMagick-c++-6.0.7.1-16.0.3")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ImageMagick-c++-6.0.7.1-16.0.3")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ImageMagick-c++-devel-6.0.7.1-16.0.3")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ImageMagick-c++-devel-6.0.7.1-16.0.3")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ImageMagick-devel-6.0.7.1-16.0.3")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ImageMagick-devel-6.0.7.1-16.0.3")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ImageMagick-perl-6.0.7.1-16.0.3")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ImageMagick-perl-6.0.7.1-16.0.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
}
