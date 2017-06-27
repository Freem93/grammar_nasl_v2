#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-069.
#

include("compat.inc");

if (description)
{
  script_id(13677);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/21 21:09:30 $");

  script_cve_id("CVE-2004-0083", "CVE-2004-0084");
  script_xref(name:"FEDORA", value:"2004-069");

  script_name(english:"Fedora Core 1 : XFree86-4.3.0-55 (2004-069)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated XFree86 packages that fix a privilege escalation vulnerability
are now available.

XFree86 is an implementation of the X Window System, providing the
core graphical user interface and video drivers.

iDefense discovered two buffer overflows in the parsing of the
'font.alias' file. A local attacker could exploit this vulnerability
by creating a carefully-crafted file and gaining root privileges. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2004-0083 and CVE-2004-0084 to these issues.

Additionally David Dawes discovered additional flaws in reading font
files. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0106 to these issues.

All users of XFree86 are advised to upgrade to these erratum packages,
which contain a backported fix and are not vulnerable to these issues.

Red Hat would like to thank David Dawes from XFree86 for the patches
and notification of these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-February/000062.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b572a94"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-ISO8859-14-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-ISO8859-14-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-ISO8859-15-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-ISO8859-15-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-ISO8859-2-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-ISO8859-2-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-ISO8859-9-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-ISO8859-9-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-Mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-Mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-base-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-cyrillic-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-libs-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-syriac-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-truetype-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-xauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:XFree86-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 1.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-100dpi-fonts-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-75dpi-fonts-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-ISO8859-14-100dpi-fonts-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-ISO8859-14-75dpi-fonts-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-ISO8859-15-100dpi-fonts-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-ISO8859-15-75dpi-fonts-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-ISO8859-2-100dpi-fonts-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-ISO8859-2-75dpi-fonts-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-ISO8859-9-100dpi-fonts-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-ISO8859-9-75dpi-fonts-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-Mesa-libGL-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-Mesa-libGLU-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-Xnest-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-Xvfb-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-base-fonts-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-cyrillic-fonts-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-devel-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-doc-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-font-utils-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-libs-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-libs-data-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-sdk-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-syriac-fonts-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-tools-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-truetype-fonts-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-twm-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-xauth-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-xdm-4.3.0-55")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"XFree86-xfs-4.3.0-55")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "XFree86 / XFree86-100dpi-fonts / XFree86-75dpi-fonts / etc");
}
