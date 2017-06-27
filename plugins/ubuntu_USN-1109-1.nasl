#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1109-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53408);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2010-4540", "CVE-2010-4541", "CVE-2010-4542", "CVE-2010-4543");
  script_bugtraq_id(45647);
  script_xref(name:"USN", value:"1109-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : gimp vulnerabilities (USN-1109-1)");
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
"It was discovered that GIMP incorrectly handled malformed data in
certain plugin configuration files. If a user were tricked into
opening a specially crafted plugin configuration file, an attacker
could cause GIMP to crash, or possibly execute arbitrary code with the
user's privileges. The default compiler options for affected releases
should reduce the vulnerability to a denial of service.
(CVE-2010-4540, CVE-2010-4541, CVE-2010-4542)

It was discovered that GIMP incorrectly handled malformed PSP image
files. If a user were tricked into opening a specially crafted PSP
image file, an attacker could cause GIMP to crash, or possibly execute
arbitrary code with the user's privileges. (CVE-2010-4543).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gimp-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gimp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gimp-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gimp-libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gimp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgimp2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgimp2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgimp2.0-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"gimp", pkgver:"2.4.5-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gimp-data", pkgver:"2.4.5-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gimp-dbg", pkgver:"2.4.5-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gimp-gnomevfs", pkgver:"2.4.5-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gimp-libcurl", pkgver:"2.4.5-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gimp-python", pkgver:"2.4.5-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgimp2.0", pkgver:"2.4.5-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgimp2.0-dev", pkgver:"2.4.5-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgimp2.0-doc", pkgver:"2.4.5-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"gimp", pkgver:"2.6.7-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"gimp-data", pkgver:"2.6.7-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"gimp-dbg", pkgver:"2.6.7-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgimp2.0", pkgver:"2.6.7-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgimp2.0-dev", pkgver:"2.6.7-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libgimp2.0-doc", pkgver:"2.6.7-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"gimp", pkgver:"2.6.8-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"gimp-data", pkgver:"2.6.8-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"gimp-dbg", pkgver:"2.6.8-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libgimp2.0", pkgver:"2.6.8-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libgimp2.0-dev", pkgver:"2.6.8-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libgimp2.0-doc", pkgver:"2.6.8-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"gimp", pkgver:"2.6.10-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"gimp-data", pkgver:"2.6.10-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"gimp-dbg", pkgver:"2.6.10-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libgimp2.0", pkgver:"2.6.10-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libgimp2.0-dev", pkgver:"2.6.10-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libgimp2.0-doc", pkgver:"2.6.10-1ubuntu3.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp / gimp-data / gimp-dbg / gimp-gnomevfs / gimp-libcurl / etc");
}
