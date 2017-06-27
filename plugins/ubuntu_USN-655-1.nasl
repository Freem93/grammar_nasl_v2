#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-655-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37662);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:37:17 $");

  script_cve_id("CVE-2007-6353", "CVE-2008-2696");
  script_bugtraq_id(26918);
  script_xref(name:"USN", value:"655-1");

  script_name(english:"Ubuntu 7.04 / 7.10 / 8.04 LTS : exiv2 vulnerabilities (USN-655-1)");
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
"Meder Kydyraliev discovered that exiv2 did not correctly handle
certain EXIF headers. If a user or automated system were tricked into
processing a specially crafted image, a remote attacker could cause
the application linked against libexiv2 to crash, leading to a denial
of service, or possibly executing arbitrary code with user privileges.
(CVE-2007-6353)

Joakim Bildrulle discovered that exiv2 did not correctly handle Nikon
lens EXIF information. If a user or automated system were tricked into
processing a specially crafted image, a remote attacker could cause
the application linked against libexiv2 to crash, leading to a denial
of service. (CVE-2008-2696).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexiv2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexiv2-0.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexiv2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexiv2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexiv2-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(7\.04|7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 7.04 / 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"7.04", pkgname:"exiv2", pkgver:"0.12-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libexiv2-0.12", pkgver:"0.12-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libexiv2-dev", pkgver:"0.12-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libexiv2-doc", pkgver:"0.12-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"exiv2", pkgver:"0.15-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libexiv2-0", pkgver:"0.15-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libexiv2-dev", pkgver:"0.15-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libexiv2-doc", pkgver:"0.15-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"exiv2", pkgver:"0.16-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libexiv2-2", pkgver:"0.16-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libexiv2-dev", pkgver:"0.16-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libexiv2-doc", pkgver:"0.16-3ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exiv2 / libexiv2-0 / libexiv2-0.12 / libexiv2-2 / libexiv2-dev / etc");
}
