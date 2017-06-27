#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0101 and 
# Oracle Linux Security Advisory ELSA-2010-0101 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67995);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:57:51 $");

  script_cve_id("CVE-2009-2949", "CVE-2009-2950", "CVE-2009-3301", "CVE-2009-3302");
  script_bugtraq_id(38218);
  script_osvdb_id(62382, 62383, 62384, 62385);
  script_xref(name:"RHSA", value:"2010:0101");

  script_name(english:"Oracle Linux 3 / 4 : openoffice.org (ELSA-2010-0101)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0101 :

Updated openoffice.org packages that correct multiple security issues
are now available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

OpenOffice.org is an office productivity suite that includes desktop
applications, such as a word processor, spreadsheet application,
presentation manager, formula editor, and a drawing program.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way OpenOffice.org parsed XPM files. An attacker could
create a specially crafted document, which once opened by a local,
unsuspecting user, could lead to arbitrary code execution with the
permissions of the user running OpenOffice.org. Note: This flaw
affects embedded XPM files in OpenOffice.org documents as well as
stand-alone XPM files. (CVE-2009-2949)

An integer underflow flaw and a boundary error flaw, both possibly
leading to a heap-based buffer overflow, were found in the way
OpenOffice.org parsed certain records in Microsoft Word documents. An
attacker could create a specially crafted Microsoft Word document,
which once opened by a local, unsuspecting user, could cause
OpenOffice.org to crash or, potentially, execute arbitrary code with
the permissions of the user running OpenOffice.org. (CVE-2009-3301,
CVE-2009-3302)

A heap-based buffer overflow flaw, leading to memory corruption, was
found in the way OpenOffice.org parsed GIF files. An attacker could
create a specially crafted document, which once opened by a local,
unsuspecting user, could cause OpenOffice.org to crash. Note: This
flaw affects embedded GIF files in OpenOffice.org documents as well as
stand-alone GIF files. (CVE-2009-2950)

All users of OpenOffice.org are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
All running instances of OpenOffice.org applications must be restarted
for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-February/001352.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-February/001353.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openoffice.org packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openoffice.org-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openoffice.org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openoffice.org-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/12");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"openoffice.org-1.1.2-46.2.0.EL3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"openoffice.org-1.1.2-46.2.0.EL3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"openoffice.org-i18n-1.1.2-46.2.0.EL3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"openoffice.org-i18n-1.1.2-46.2.0.EL3")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"openoffice.org-libs-1.1.2-46.2.0.EL3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"openoffice.org-libs-1.1.2-46.2.0.EL3")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"openoffice.org-1.1.5-10.6.0.7.EL4.3")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"openoffice.org-1.1.5-10.6.0.7.EL4.3")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"openoffice.org-i18n-1.1.5-10.6.0.7.EL4.3")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"openoffice.org-i18n-1.1.5-10.6.0.7.EL4.3")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"openoffice.org-kde-1.1.5-10.6.0.7.EL4.3")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"openoffice.org-libs-1.1.5-10.6.0.7.EL4.3")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"openoffice.org-libs-1.1.5-10.6.0.7.EL4.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openoffice.org / openoffice.org-i18n / openoffice.org-kde / etc");
}
