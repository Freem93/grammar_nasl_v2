#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2006:0633 and 
# Oracle Linux Security Advisory ELSA-2006-0633 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67403);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:16:26 $");

  script_cve_id("CVE-2006-3743", "CVE-2006-3744", "CVE-2006-4144");
  script_bugtraq_id(19507, 19697, 19699);
  script_osvdb_id(27951);
  script_xref(name:"RHSA", value:"2006:0633");

  script_name(english:"Oracle Linux 4 : ImageMagick (ELSA-2006-0633)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2006:0633 :

Updated ImageMagick packages that fix several security issues are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

ImageMagick(TM) is an image display and manipulation tool for the X
Window System that can read and write multiple image formats.

Tavis Ormandy discovered several integer and buffer overflow flaws in
the way ImageMagick decodes XCF, SGI, and Sun bitmap graphic files. An
attacker could execute arbitrary code on a victim's machine if they
were able to trick the victim into opening a specially crafted image
file. (CVE-2006-3743, CVE-2006-3744, CVE-2006-4144)

Users of ImageMagick should upgrade to these updated packages, which
contain backported patches and are not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2006-November/000002.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected imagemagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/14");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ImageMagick-6.0.7.1-16")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ImageMagick-6.0.7.1-16")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ImageMagick-c++-6.0.7.1-16")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ImageMagick-c++-6.0.7.1-16")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ImageMagick-c++-devel-6.0.7.1-16")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ImageMagick-c++-devel-6.0.7.1-16")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ImageMagick-devel-6.0.7.1-16")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ImageMagick-devel-6.0.7.1-16")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ImageMagick-perl-6.0.7.1-16")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ImageMagick-perl-6.0.7.1-16")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
}
