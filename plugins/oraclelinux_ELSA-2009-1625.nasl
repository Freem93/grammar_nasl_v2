#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1625 and 
# Oracle Linux Security Advisory ELSA-2009-1625 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67966);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/14 17:29:37 $");

  script_cve_id("CVE-2009-3560", "CVE-2009-3720");
  script_bugtraq_id(36097, 37203);
  script_osvdb_id(59737, 60797);
  script_xref(name:"RHSA", value:"2009:1625");

  script_name(english:"Oracle Linux 3 / 4 / 5 : expat (ELSA-2009-1625)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1625 :

Updated expat packages that fix two security issues are now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Expat is a C library written by James Clark for parsing XML documents.

Two buffer over-read flaws were found in the way Expat handled
malformed UTF-8 sequences when processing XML files. A specially
crafted XML file could cause applications using Expat to crash while
parsing the file. (CVE-2009-3560, CVE-2009-3720)

All expat users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, applications using the Expat library must be
restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-December/001270.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-December/001271.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-December/001272.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected expat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:expat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:expat-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/07");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"expat-1.95.5-6.2")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"expat-1.95.5-6.2")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"expat-devel-1.95.5-6.2")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"expat-devel-1.95.5-6.2")) flag++;

if (rpm_check(release:"EL4", reference:"expat-1.95.7-4.el4_8.2")) flag++;
if (rpm_check(release:"EL4", reference:"expat-devel-1.95.7-4.el4_8.2")) flag++;

if (rpm_check(release:"EL5", reference:"expat-1.95.8-8.3.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"expat-devel-1.95.8-8.3.el5_4.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "expat / expat-devel");
}
