#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2006:0665 and 
# Oracle Linux Security Advisory ELSA-2006-0665 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67407);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/01 16:16:26 $");

  script_cve_id("CVE-2006-3739", "CVE-2006-3740");
  script_osvdb_id(28738, 28739);
  script_xref(name:"RHSA", value:"2006:0665");

  script_name(english:"Oracle Linux 4 : xorg-x11 (ELSA-2006-0665)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2006:0665 :

Updated X.org packages that fix a security issue are now available for
Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

X.org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

iDefense reported two integer overflow flaws in the way the X.org
server processed CID font files. A malicious authorized client could
exploit this issue to cause a denial of service (crash) or potentially
execute arbitrary code with root privileges on the X.org server.
(CVE-2006-3739, CVE-2006-3740)

Users of X.org should upgrade to these updated packages, which contain
a backported patch and is not vulnerable to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2006-November/000005.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-Mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-Mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-deprecated-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-deprecated-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-xauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xorg-x11-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/12");
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
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-Xdmx-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-Xdmx-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-Xnest-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-Xnest-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-Xvfb-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-Xvfb-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-devel-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-devel-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-doc-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-doc-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-font-utils-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-font-utils-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-libs-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-libs-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-sdk-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-sdk-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-tools-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-tools-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-twm-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-twm-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-xauth-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-xauth-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-xdm-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-xdm-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"xorg-x11-xfs-6.8.2-1.EL.13.37.2.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"xorg-x11-xfs-6.8.2-1.EL.13.37.2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11 / xorg-x11-Mesa-libGL / xorg-x11-Mesa-libGLU / etc");
}
