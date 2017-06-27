#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2626-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83989);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/05/24 17:44:49 $");

  script_cve_id("CVE-2014-0190", "CVE-2015-0295", "CVE-2015-1858", "CVE-2015-1859", "CVE-2015-1860");
  script_bugtraq_id(67087, 73029, 74302, 74307, 74309, 74310);
  script_osvdb_id(119072, 120574, 120575, 120576);
  script_xref(name:"USN", value:"2626-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 14.10 / 15.04 : qt4-x11, qtbase-opensource-src vulnerabilities (USN-2626-1)");
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
"Wolfgang Schenk discovered that Qt incorrectly handled certain
malformed GIF images. If a user or automated system were tricked into
opening a specially crafted GIF image, a remote attacker could use
this issue to cause Qt to crash, resulting in a denial of service.
This issue only applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2014-0190)

Fabian Vogt discovered that Qt incorrectly handled certain malformed
BMP images. If a user or automated system were tricked into opening a
specially crafted BMP image, a remote attacker could use this issue to
cause Qt to crash, resulting in a denial of service. (CVE-2015-0295)

Richard Moore and Fabian Vogt discovered that Qt incorrectly handled
certain malformed BMP images. If a user or automated system were
tricked into opening a specially crafted BMP image, a remote attacker
could use this issue to cause Qt to crash, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2015-1858)

Richard Moore and Fabian Vogt discovered that Qt incorrectly handled
certain malformed ICO images. If a user or automated system were
tricked into opening a specially crafted ICO image, a remote attacker
could use this issue to cause Qt to crash, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2015-1859)

Richard Moore and Fabian Vogt discovered that Qt incorrectly handled
certain malformed GIF images. If a user or automated system were
tricked into opening a specially crafted GIF image, a remote attacker
could use this issue to cause Qt to crash, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2015-1860).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libqt5gui5 and / or libqtgui4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqt5gui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libqtgui4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|14\.10|15\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 14.10 / 15.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libqtgui4", pkgver:"4:4.8.1-0ubuntu4.9")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libqt5gui5", pkgver:"5.2.1+dfsg-1ubuntu14.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libqtgui4", pkgver:"4:4.8.5+git192-g085f851+dfsg-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"libqt5gui5", pkgver:"5.3.0+dfsg-2ubuntu9.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"libqtgui4", pkgver:"4:4.8.6+git49-gbc62005+dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libqt5gui5", pkgver:"5.4.1+dfsg-2ubuntu4.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libqtgui4", pkgver:"4:4.8.6+git64-g5dc8b2b+dfsg-3~ubuntu6.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libqt5gui5 / libqtgui4");
}
