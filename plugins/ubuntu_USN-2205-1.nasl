#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2205-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73902);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/23 14:38:51 $");

  script_cve_id("CVE-2013-4231", "CVE-2013-4232", "CVE-2013-4243", "CVE-2013-4244");
  script_bugtraq_id(61695, 61849, 62019, 62082);
  script_osvdb_id(96203, 96204, 96205, 96206, 96207, 96649, 96783);
  script_xref(name:"USN", value:"2205-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 12.10 / 13.10 / 14.04 LTS : tiff vulnerabilities (USN-2205-1)");
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
"Pedro Ribeiro discovered that LibTIFF incorrectly handled certain
malformed images when using the gif2tiff tool. If a user or automated
system were tricked into opening a specially crafted GIF image, a
remote attacker could crash the application, leading to a denial of
service, or possibly execute arbitrary code with user privileges. This
issue only affected Ubuntu 10.04 LTS, Ubunu 12.04 LTS, Ubuntu 12.10
and Ubuntu 13.10. (CVE-2013-4231)

Pedro Ribeiro discovered that LibTIFF incorrectly handled certain
malformed images when using the tiff2pdf tool. If a user or automated
system were tricked into opening a specially crafted TIFF image, a
remote attacker could crash the application, leading to a denial of
service, or possibly execute arbitrary code with user privileges. This
issue only affected Ubuntu 10.04 LTS, Ubunu 12.04 LTS, Ubuntu 12.10
and Ubuntu 13.10. (CVE-2013-4232)

Murray McAllister discovered that LibTIFF incorrectly handled certain
malformed images when using the gif2tiff tool. If a user or automated
system were tricked into opening a specially crafted GIF image, a
remote attacker could crash the application, leading to a denial of
service, or possibly execute arbitrary code with user privileges.
(CVE-2013-4243)

Huzaifa Sidhpurwala discovered that LibTIFF incorrectly handled
certain malformed images when using the gif2tiff tool. If a user or
automated system were tricked into opening a specially crafted GIF
image, a remote attacker could crash the application, leading to a
denial of service, or possibly execute arbitrary code with user
privileges. This issue only affected Ubuntu 10.04 LTS, Ubunu 12.04
LTS, Ubuntu 12.10 and Ubuntu 13.10. (CVE-2013-4244).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff4 and / or libtiff5 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|12\.04|12\.10|13\.10|14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 12.10 / 13.10 / 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libtiff4", pkgver:"3.9.2-2ubuntu0.14")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libtiff4", pkgver:"3.9.5-2ubuntu1.6")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libtiff5", pkgver:"4.0.2-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"libtiff5", pkgver:"4.0.2-4ubuntu3.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libtiff5", pkgver:"4.0.3-7ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff4 / libtiff5");
}
