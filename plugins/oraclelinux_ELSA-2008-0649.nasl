#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0649 and 
# Oracle Linux Security Advisory ELSA-2008-0649 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67734);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 16:41:02 $");

  script_cve_id("CVE-2008-2935");
  script_bugtraq_id(30467);
  script_osvdb_id(47544);
  script_xref(name:"RHSA", value:"2008:0649");

  script_name(english:"Oracle Linux 4 / 5 : libxslt (ELSA-2008-0649)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0649 :

Updated libxslt packages that fix a security issue are now available
for Red Hat Enterprise Linux 4 and Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

libxslt is a library for transforming XML files into other XML files
using the standard XSLT stylesheet transformation mechanism.

A heap buffer overflow flaw was discovered in the RC4 libxslt library
extension. An attacker could create a malicious XSL file that would
cause a crash, or, possibly, execute arbitrary code with the
privileges of the application using the libxslt library to perform XSL
transformations on untrusted XSL style sheets. (CVE-2008-2935)

Red Hat would like to thank Chris Evans for reporting this
vulnerability.

All libxslt users are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-August/000698.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-July/000697.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxslt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxslt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxslt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxslt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
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
if (rpm_check(release:"EL4", reference:"libxslt-1.1.11-1.0.1.el4_7.2")) flag++;
if (rpm_check(release:"EL4", reference:"libxslt-devel-1.1.11-1.0.1.el4_7.2")) flag++;
if (rpm_check(release:"EL4", reference:"libxslt-python-1.1.11-1.0.1.el4_7.2")) flag++;

if (rpm_check(release:"EL5", reference:"libxslt-1.1.17-2.0.1.el5_2.2")) flag++;
if (rpm_check(release:"EL5", reference:"libxslt-devel-1.1.17-2.0.1.el5_2.2")) flag++;
if (rpm_check(release:"EL5", reference:"libxslt-python-1.1.17-2.0.1.el5_2.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxslt / libxslt-devel / libxslt-python");
}
