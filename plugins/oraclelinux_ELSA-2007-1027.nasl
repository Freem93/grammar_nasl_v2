#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:1027 and 
# Oracle Linux Security Advisory ELSA-2007-1027 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67604);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:16:28 $");

  script_cve_id("CVE-2007-4033", "CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_bugtraq_id(26367);
  script_osvdb_id(38698, 39541, 39542, 39543);
  script_xref(name:"RHSA", value:"2007:1027");

  script_name(english:"Oracle Linux 4 : tetex (ELSA-2007-1027)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:1027 :

Updated tetex packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

TeTeX is an implementation of TeX. TeX takes a text file and a set of
formatting commands as input, and creates a typesetter-independent
DeVice Independent (dvi) file as output.

Alin Rad Pop discovered several flaws in the handling of PDF files. An
attacker could create a malicious PDF file that would cause TeTeX to
crash or potentially execute arbitrary code when opened.
(CVE-2007-4352, CVE-2007-5392, CVE-2007-5393)

A flaw was found in the t1lib library, used in the handling of Type 1
fonts. An attacker could create a malicious file that would cause
TeTeX to crash, or potentially execute arbitrary code when opened.
(CVE-2007-4033)

Users are advised to upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-November/000392.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tetex packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tetex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/27");
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
if (rpm_check(release:"EL4", cpu:"i386", reference:"tetex-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"tetex-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"tetex-afm-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"tetex-afm-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"tetex-doc-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"tetex-doc-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"tetex-dvips-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"tetex-dvips-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"tetex-fonts-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"tetex-fonts-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"tetex-latex-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"tetex-latex-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"tetex-xdvi-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"tetex-xdvi-2.0.2-22.0.1.EL4.10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tetex / tetex-afm / tetex-doc / tetex-dvips / tetex-fonts / etc");
}
