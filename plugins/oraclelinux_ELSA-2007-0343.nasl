#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0343 and 
# Oracle Linux Security Advisory ELSA-2007-0343 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67491);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 16:16:27 $");

  script_cve_id("CVE-2007-2356");
  script_bugtraq_id(23680);
  script_osvdb_id(35417);
  script_xref(name:"RHSA", value:"2007:0343");

  script_name(english:"Oracle Linux 3 / 4 / 5 : gimp (ELSA-2007-0343)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0343 :

Updated gimp packages that fix a security issue are now available for
Red Hat Enterprise Linux.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The GIMP (GNU Image Manipulation Program) is an image composition and
editing program.

Marsu discovered a stack overflow bug in The GIMP RAS file loader. An
attacker could create a carefully crafted file that could cause The
GIMP to crash or possibly execute arbitrary code if the file was
opened by a victim. (CVE-2007-2356)

For users of Red Hat Enterprise Linux 5, the previous GIMP packages
had a bug that concerned the execution order in which the symbolic
links to externally packaged GIMP plugins are installed and removed,
causing the symbolic links to vanish when the package is updated.

Users of The GIMP should update to these erratum packages which
contain a backported fix to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-June/000226.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-May/000158.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-May/000159.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gimp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gimp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gimp-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/26");
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
if (rpm_check(release:"EL3", cpu:"i386", reference:"gimp-1.2.3-20.3.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"gimp-1.2.3-20.3.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"gimp-devel-1.2.3-20.3.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"gimp-devel-1.2.3-20.3.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"gimp-perl-1.2.3-20.3.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"gimp-perl-1.2.3-20.3.el3")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"gimp-2.0.5-6.2.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"gimp-2.0.5-6.2.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"gimp-devel-2.0.5-6.2.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"gimp-devel-2.0.5-6.2.el4")) flag++;

if (rpm_check(release:"EL5", reference:"gimp-2.2.13-2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"gimp-devel-2.2.13-2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"gimp-libs-2.2.13-2.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp / gimp-devel / gimp-libs / gimp-perl");
}
