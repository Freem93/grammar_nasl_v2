#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-861-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42891);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:45:43 $");

  script_cve_id("CVE-2008-2009", "CVE-2009-3379");
  script_bugtraq_id(36875);
  script_xref(name:"USN", value:"861-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 / 9.10 : libvorbis vulnerabilities (USN-861-1)");
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
"It was discovered that libvorbis did not correctly handle ogg files
with underpopulated Huffman trees. If a user were tricked into opening
a specially crafted ogg file with an application that uses libvorbis,
an attacker could cause a denial of service. (CVE-2008-2009)

It was discovered that libvorbis did not correctly handle certain
malformed ogg files. If a user were tricked into opening a specially
crafted ogg file with an application that uses libvorbis, an attacker
could cause a denial of service or possibly execute arbitrary code
with the user's privileges. (CVE-2009-3379).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvorbis-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvorbis0a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvorbisenc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvorbisfile3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libvorbis-dev", pkgver:"1.2.0.dfsg-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libvorbis0a", pkgver:"1.2.0.dfsg-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libvorbisenc2", pkgver:"1.2.0.dfsg-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libvorbisfile3", pkgver:"1.2.0.dfsg-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libvorbis-dev", pkgver:"1.2.0.dfsg-3.1ubuntu0.8.10.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libvorbis0a", pkgver:"1.2.0.dfsg-3.1ubuntu0.8.10.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libvorbisenc2", pkgver:"1.2.0.dfsg-3.1ubuntu0.8.10.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libvorbisfile3", pkgver:"1.2.0.dfsg-3.1ubuntu0.8.10.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libvorbis-dev", pkgver:"1.2.0.dfsg-3.1ubuntu0.9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libvorbis0a", pkgver:"1.2.0.dfsg-3.1ubuntu0.9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libvorbisenc2", pkgver:"1.2.0.dfsg-3.1ubuntu0.9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libvorbisfile3", pkgver:"1.2.0.dfsg-3.1ubuntu0.9.04.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libvorbis-dev", pkgver:"1.2.0.dfsg-6ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libvorbis0a", pkgver:"1.2.0.dfsg-6ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libvorbisenc2", pkgver:"1.2.0.dfsg-6ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libvorbisfile3", pkgver:"1.2.0.dfsg-6ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvorbis-dev / libvorbis0a / libvorbisenc2 / libvorbisfile3");
}
