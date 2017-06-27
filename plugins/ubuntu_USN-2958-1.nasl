#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2958-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90858);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/01 21:07:49 $");

  script_cve_id("CVE-2013-4473", "CVE-2013-4474", "CVE-2015-8868");
  script_osvdb_id(99065, 99066, 132203);
  script_xref(name:"USN", value:"2958-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 : poppler vulnerabilities (USN-2958-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the poppler pdfseparate tool incorrectly
handled certain filenames. A local attacker could use this issue to
cause the tool to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only applied to Ubuntu 12.04 LTS.
(CVE-2013-4473, CVE-2013-4474)

It was discovered that poppler incorrectly parsed certain malformed
PDF documents. If a user or automated system were tricked into opening
a crafted PDF file, an attacker could cause a denial of service or
possibly execute arbitrary code with privileges of the user invoking
the program. (CVE-2015-8868).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-cpp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-glib8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt4-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt4-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt5-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler44");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(12\.04|14\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libpoppler-cpp0", pkgver:"0.18.4-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libpoppler-glib8", pkgver:"0.18.4-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libpoppler-qt4-3", pkgver:"0.18.4-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libpoppler19", pkgver:"0.18.4-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"poppler-utils", pkgver:"0.18.4-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libpoppler-cpp0", pkgver:"0.24.5-2ubuntu4.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libpoppler-glib8", pkgver:"0.24.5-2ubuntu4.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libpoppler-qt4-4", pkgver:"0.24.5-2ubuntu4.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libpoppler-qt5-1", pkgver:"0.24.5-2ubuntu4.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libpoppler44", pkgver:"0.24.5-2ubuntu4.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"poppler-utils", pkgver:"0.24.5-2ubuntu4.4")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libpoppler-cpp0", pkgver:"0.33.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libpoppler-glib8", pkgver:"0.33.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libpoppler-qt4-4", pkgver:"0.33.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libpoppler-qt5-1", pkgver:"0.33.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libpoppler52", pkgver:"0.33.0-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"poppler-utils", pkgver:"0.33.0-0ubuntu3.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpoppler-cpp0 / libpoppler-glib8 / libpoppler-qt4-3 / etc");
}
