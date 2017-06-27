#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0001 and 
# Oracle Linux Security Advisory ELSA-2007-0001 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67433);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:16:26 $");

  script_cve_id("CVE-2006-5870");
  script_bugtraq_id(21861);
  script_osvdb_id(32610, 32611);
  script_xref(name:"RHSA", value:"2007:0001");

  script_name(english:"Oracle Linux 4 : openoffice.org (ELSA-2007-0001)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0001 :

Updated openoffice.org packages are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

OpenOffice.org is an office productivity suite that includes desktop
applications such as a word processor, spreadsheet, presentation
manager, formula editor, and drawing program.

Several integer overflow bugs were found in the OpenOffice.org WMF
file processor. An attacker could create a carefully crafted WMF file
that could cause OpenOffice.org to execute arbitrary code when the
file was opened by a victim. (CVE-2006-5870)

All users of OpenOffice.org are advised to upgrade to these updated
packages, which contain a backported fix for this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-January/000038.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openoffice.org packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openoffice.org-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openoffice.org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openoffice.org-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/04");
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
if (rpm_check(release:"EL4", cpu:"i386", reference:"openoffice.org-1.1.5-6.6.0.EL4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"openoffice.org-1.1.5-6.6.0.EL4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"openoffice.org-i18n-1.1.5-6.6.0.EL4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"openoffice.org-i18n-1.1.5-6.6.0.EL4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"openoffice.org-kde-1.1.5-6.6.0.EL4")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"openoffice.org-libs-1.1.5-6.6.0.EL4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"openoffice.org-libs-1.1.5-6.6.0.EL4")) flag++;


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
