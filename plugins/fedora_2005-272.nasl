#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-272.
#

include("compat.inc");

if (description)
{
  script_id(18328);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:38:04 $");

  script_cve_id("CVE-2005-0605");
  script_xref(name:"FEDORA", value:"2005-272");

  script_name(english:"Fedora Core 2 : xorg-x11-6.7.0-14 (2005-272)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer overflow flaw was found in libXpm, which is used by some
applications for loading of XPM images. An attacker could create a
malicious XPM file that would execute arbitrary code if opened by a
victim using an application linked to the vulnerable library. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0605 to this issue.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-March/000816.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c8ed366"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-ISO8859-14-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-ISO8859-14-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-ISO8859-15-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-ISO8859-15-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-ISO8859-2-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-ISO8859-2-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-ISO8859-9-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-ISO8859-9-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-Mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-Mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-base-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-cyrillic-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-libs-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-syriac-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-truetype-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-xauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/19");
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
if (! ereg(pattern:"^2([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 2.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC2", reference:"xorg-x11-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-100dpi-fonts-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-75dpi-fonts-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-ISO8859-14-100dpi-fonts-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-ISO8859-14-75dpi-fonts-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-ISO8859-15-100dpi-fonts-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-ISO8859-15-75dpi-fonts-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-ISO8859-2-100dpi-fonts-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-ISO8859-2-75dpi-fonts-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-ISO8859-9-100dpi-fonts-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-ISO8859-9-75dpi-fonts-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-Mesa-libGL-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-Mesa-libGLU-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-Xnest-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-Xvfb-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-base-fonts-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-cyrillic-fonts-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-devel-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-doc-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-font-utils-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-libs-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-libs-data-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-sdk-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-syriac-fonts-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-tools-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-truetype-fonts-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-twm-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-xauth-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-xdm-6.7.0-14")) flag++;
if (rpm_check(release:"FC2", reference:"xorg-x11-xfs-6.7.0-14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11 / xorg-x11-100dpi-fonts / xorg-x11-75dpi-fonts / etc");
}
