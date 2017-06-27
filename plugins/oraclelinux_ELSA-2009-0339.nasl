#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:0339 and 
# Oracle Linux Security Advisory ELSA-2009-0339 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67819);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:57:50 $");

  script_cve_id("CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733");
  script_osvdb_id(56307, 56308);
  script_xref(name:"RHSA", value:"2009:0339");

  script_name(english:"Oracle Linux 5 : lcms (ELSA-2009-0339)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:0339 :

Updated lcms packages that resolve several security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Little Color Management System (LittleCMS, or simply 'lcms') is a
small-footprint, speed-optimized open source color management engine.

Multiple integer overflow flaws which could lead to heap-based buffer
overflows, as well as multiple insufficient input validation flaws,
were found in LittleCMS. An attacker could use these flaws to create a
specially crafted image file which could cause an application using
LittleCMS to crash, or, possibly, execute arbitrary code when opened
by a victim. (CVE-2009-0723, CVE-2009-0733)

A memory leak flaw was found in LittleCMS. An application using
LittleCMS could use excessive amount of memory, and possibly crash
after using all available memory, if used to open specially crafted
images. (CVE-2009-0581)

Red Hat would like to thank Chris Evans from the Google Security Team
for reporting these issues.

All users of LittleCMS should install these updated packages, which
upgrade LittleCMS to version 1.18. All running applications using the
lcms library must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-March/000923.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lcms packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:lcms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:lcms-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-lcms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"lcms-1.18-0.1.beta1.el5_3.2")) flag++;
if (rpm_check(release:"EL5", reference:"lcms-devel-1.18-0.1.beta1.el5_3.2")) flag++;
if (rpm_check(release:"EL5", reference:"python-lcms-1.18-0.1.beta1.el5_3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lcms / lcms-devel / python-lcms");
}
