#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3213-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97468);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/03 14:52:26 $");

  script_cve_id("CVE-2016-10166", "CVE-2016-10167", "CVE-2016-10168", "CVE-2016-6906", "CVE-2016-6912", "CVE-2016-9317", "CVE-2016-9933");
  script_osvdb_id(125857, 150557, 150562, 150575, 150576, 150614, 150680);
  script_xref(name:"USN", value:"3213-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 : libgd2 vulnerabilities (USN-3213-1)");
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
"Stefan Esser discovered that the GD library incorrectly handled memory
when processing certain images. If a user or automated system were
tricked into processing a specially crafted image, an attacker could
cause a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu
16.10. (CVE-2016-10166)

It was discovered that the GD library incorrectly handled certain
malformed images. If a user or automated system were tricked into
processing a specially crafted image, an attacker could cause a denial
of service. (CVE-2016-10167)

It was discovered that the GD library incorrectly handled certain
malformed images. If a user or automated system were tricked into
processing a specially crafted image, an attacker could cause a denial
of service, or possibly execute arbitrary code. (CVE-2016-10168)

Ibrahim El-Sayed discovered that the GD library incorrectly handled
certain malformed TGA images. If a user or automated system were
tricked into processing a specially crafted TGA image, an attacker
could cause a denial of service. This issue only affected Ubuntu 14.04
LTS, Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-6906)

Ibrahim El-Sayed discovered that the GD library incorrectly handled
certain malformed WebP images. If a user or automated system were
tricked into processing a specially crafted WebP image, an attacker
could cause a denial of service, or possibly execute arbitrary code.
This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu
16.10. (CVE-2016-6912)

It was discovered that the GD library incorrectly handled creating
oversized images. If a user or automated system were tricked into
creating a specially crafted image, an attacker could cause a denial
of service. (CVE-2016-9317)

It was discovered that the GD library incorrectly handled filling
certain images. If a user or automated system were tricked into
filling an image, an attacker could cause a denial of service.
(CVE-2016-9933).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgd2-noxpm, libgd2-xpm and / or libgd3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd2-noxpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd2-xpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgd3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017 Canonical, Inc. / NASL script (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libgd2-noxpm", pkgver:"2.0.36~rc1~dfsg-6ubuntu2.4")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgd2-xpm", pkgver:"2.0.36~rc1~dfsg-6ubuntu2.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libgd3", pkgver:"2.1.0-3ubuntu0.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libgd3", pkgver:"2.1.1-4ubuntu0.16.04.6")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libgd3", pkgver:"2.2.1-1ubuntu3.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgd2-noxpm / libgd2-xpm / libgd3");
}
