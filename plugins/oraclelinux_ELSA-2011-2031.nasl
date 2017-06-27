#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2011-2031.
#

include("compat.inc");

if (description)
{
  script_id(68423);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/12/02 05:38:31 $");

  script_cve_id("CVE-2011-2306");
  script_xref(name:"IAVA", value:"2011-A-0143");

  script_name(english:"Oracle Linux 4 / 5 : oracle-validated (ELSA-2011-2031)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

- Fix for security bug CVE-2011-2306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-October/002402.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-October/002403.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected oracle-validated package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracle-validated");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", sp:"4", cpu:"i386", reference:"oracle-validated-1.0.0-18.1.el4")) flag++;
if (rpm_check(release:"EL4", sp:"4", cpu:"x86_64", reference:"oracle-validated-1.0.0-18.1.el4")) flag++;
if (rpm_check(release:"EL4", sp:"5", cpu:"i386", reference:"oracle-validated-1.0.0-18.1.el4")) flag++;
if (rpm_check(release:"EL4", sp:"5", cpu:"x86_64", reference:"oracle-validated-1.0.0-18.1.el4")) flag++;
if (rpm_check(release:"EL4", sp:"6", cpu:"i386", reference:"oracle-validated-1.0.0-18.1.el4")) flag++;
if (rpm_check(release:"EL4", sp:"6", cpu:"x86_64", reference:"oracle-validated-1.0.0-18.1.el4")) flag++;
if (rpm_check(release:"EL4", sp:"7", cpu:"i386", reference:"oracle-validated-1.0.0-26.el4")) flag++;
if (rpm_check(release:"EL4", sp:"7", cpu:"x86_64", reference:"oracle-validated-1.0.0-26.el4")) flag++;
if (rpm_check(release:"EL4", sp:"8", cpu:"i386", reference:"oracle-validated-1.0.0-26.el4")) flag++;
if (rpm_check(release:"EL4", sp:"8", cpu:"x86_64", reference:"oracle-validated-1.0.0-26.el4")) flag++;

if (rpm_check(release:"EL5", sp:"0", reference:"oracle-validated-1.0.0-18.1.el5")) flag++;
if (rpm_check(release:"EL5", sp:"1", reference:"oracle-validated-1.0.0-18.1.el5")) flag++;
if (rpm_check(release:"EL5", sp:"2", reference:"oracle-validated-1.0.0-26.el5")) flag++;
if (rpm_check(release:"EL5", sp:"3", reference:"oracle-validated-1.0.0-26.el5")) flag++;
if (rpm_check(release:"EL5", sp:"4", reference:"oracle-validated-1.0.0-26.el5")) flag++;
if (rpm_check(release:"EL5", sp:"5", reference:"oracle-validated-1.0.0-26.el5")) flag++;
if (rpm_check(release:"EL5", sp:"6", cpu:"i386", reference:"oracle-validated-1.0.0-26.el5")) flag++;
if (rpm_check(release:"EL5", sp:"6", cpu:"x86_64", reference:"oracle-validated-1.1.0-12.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "oracle-validated");
}
