#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0401 and 
# Oracle Linux Security Advisory ELSA-2010-0401 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68040);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:57:51 $");

  script_cve_id("CVE-2007-5935", "CVE-2009-0791", "CVE-2009-3609", "CVE-2010-0739", "CVE-2010-0827", "CVE-2010-1440");
  script_bugtraq_id(26469, 35195, 36703, 39966);
  script_xref(name:"RHSA", value:"2010:0401");

  script_name(english:"Oracle Linux 3 : tetex (ELSA-2010-0401)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0401 :

Updated tetex packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 3.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

teTeX is an implementation of TeX. TeX takes a text file and a set of
formatting commands as input, and creates a typesetter-independent
DeVice Independent (DVI) file as output.

A buffer overflow flaw was found in the way teTeX processed virtual
font files when converting DVI files into PostScript. An attacker
could create a malicious DVI file that would cause the dvips
executable to crash or, potentially, execute arbitrary code.
(CVE-2010-0827)

Multiple integer overflow flaws were found in the way teTeX processed
special commands when converting DVI files into PostScript. An
attacker could create a malicious DVI file that would cause the dvips
executable to crash or, potentially, execute arbitrary code.
(CVE-2010-0739, CVE-2010-1440)

A stack-based buffer overflow flaw was found in the way teTeX
processed DVI files containing HyperTeX references with long titles,
when converting them into PostScript. An attacker could create a
malicious DVI file that would cause the dvips executable to crash.
(CVE-2007-5935)

teTeX embeds a copy of Xpdf, an open source Portable Document Format
(PDF) file viewer, to allow adding images in PDF format to the
generated PDF documents. The following issues affect Xpdf code :

Multiple integer overflow flaws were found in Xpdf. If a local user
generated a PDF file from a TeX document, referencing a specially
crafted PDF file, it would cause Xpdf to crash or, potentially,
execute arbitrary code with the privileges of the user running
pdflatex. (CVE-2009-0791, CVE-2009-3609)

All users of tetex are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-May/001456.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tetex packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tetex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/07");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"tetex-1.0.7-67.19")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"tetex-1.0.7-67.19")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"tetex-afm-1.0.7-67.19")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"tetex-afm-1.0.7-67.19")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"tetex-dvips-1.0.7-67.19")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"tetex-dvips-1.0.7-67.19")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"tetex-fonts-1.0.7-67.19")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"tetex-fonts-1.0.7-67.19")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"tetex-latex-1.0.7-67.19")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"tetex-latex-1.0.7-67.19")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"tetex-xdvi-1.0.7-67.19")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"tetex-xdvi-1.0.7-67.19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tetex / tetex-afm / tetex-dvips / tetex-fonts / tetex-latex / etc");
}
