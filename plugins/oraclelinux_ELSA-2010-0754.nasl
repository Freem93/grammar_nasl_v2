#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0754 and 
# Oracle Linux Security Advisory ELSA-2010-0754 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68115);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/01 16:49:14 $");

  script_cve_id("CVE-2010-3702", "CVE-2010-3703", "CVE-2010-3704");
  script_xref(name:"RHSA", value:"2010:0754");

  script_name(english:"Oracle Linux 3 : cups (ELSA-2010-0754)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0754 :

Updated cups packages that fix one security issue are now available
for Red Hat Enterprise Linux 3.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX operating systems. The CUPS 'pdftops' filter converts
Portable Document Format (PDF) files to PostScript.

An uninitialized pointer use flaw was discovered in the CUPS 'pdftops'
filter. An attacker could create a malicious PDF file that, when
printed, would cause 'pdftops' to crash or, potentially, execute
arbitrary code as the 'lp' user. (CVE-2010-3702)

Users of cups are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing
this update, the cupsd daemon will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-October/001679.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/07");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"cups-1.1.17-13.3.70")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"cups-1.1.17-13.3.70")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"cups-devel-1.1.17-13.3.70")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"cups-devel-1.1.17-13.3.70")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"cups-libs-1.1.17-13.3.70")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"cups-libs-1.1.17-13.3.70")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-devel / cups-libs");
}
