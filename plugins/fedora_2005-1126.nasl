#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-1126.
#

include("compat.inc");

if (description)
{
  script_id(20278);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 21:09:33 $");

  script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193");
  script_xref(name:"FEDORA", value:"2005-1126");

  script_name(english:"Fedora Core 4 : tetex-3.0-7.FC4 (2005-1126)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several flaws were discovered in Xpdf. An attacker could construct a
carefully crafted PDF file that could cause Xpdf to crash or possibly
execute arbitrary code when opened. The teTeX package contains a copy
of the Xpdf code used for parsing PDF files and is therefore affected
by this bug.The Common Vulnerabilities and Exposures project assigned
the name CVE-2005-3193 to these issues.

Users of teTeX should upgrade to this updated package, which contains
a patch to resolve these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-December/001631.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5d295f8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tetex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tetex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 4.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC4", reference:"tetex-3.0-7.FC4")) flag++;
if (rpm_check(release:"FC4", reference:"tetex-afm-3.0-7.FC4")) flag++;
if (rpm_check(release:"FC4", reference:"tetex-debuginfo-3.0-7.FC4")) flag++;
if (rpm_check(release:"FC4", reference:"tetex-doc-3.0-7.FC4")) flag++;
if (rpm_check(release:"FC4", reference:"tetex-dvips-3.0-7.FC4")) flag++;
if (rpm_check(release:"FC4", reference:"tetex-fonts-3.0-7.FC4")) flag++;
if (rpm_check(release:"FC4", reference:"tetex-latex-3.0-7.FC4")) flag++;
if (rpm_check(release:"FC4", reference:"tetex-xdvi-3.0-7.FC4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tetex / tetex-afm / tetex-debuginfo / tetex-doc / tetex-dvips / etc");
}
