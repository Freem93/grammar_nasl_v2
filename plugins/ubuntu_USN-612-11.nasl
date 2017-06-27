#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-612-11. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33254);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:29:19 $");

  script_xref(name:"USN", value:"612-11");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 / 8.04 LTS : openssl-blacklist update (USN-612-11)");
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
"USN-612-3 addressed a weakness in OpenSSL certificate and key
generation and introduced openssl-blacklist to aid in detecting
vulnerable certificates and keys. This update adds RSA-4096 blacklists
to the openssl-blacklist-extra package and adjusts openssl-vulnkey to
properly handle RSA-4096 and higher moduli.

A weakness has been discovered in the random number generator used by
OpenSSL on Debian and Ubuntu systems. As a result of this weakness,
certain encryption keys are much more common than they should be, such
that an attacker could guess the key through a brute-force attack
given minimal knowledge of the system. This particularly affects the
use of encryption keys in OpenSSH, OpenVPN and SSL certificates.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected openssl-blacklist and / or openssl-blacklist-extra
packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl-blacklist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl-blacklist-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.04|7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.04 / 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"openssl-blacklist", pkgver:"0.3.3+0.4-0ubuntu0.6.06.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openssl-blacklist-extra", pkgver:"0.3.3+0.4-0ubuntu0.6.06.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"openssl-blacklist", pkgver:"0.3.3+0.4-0ubuntu0.7.04.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"openssl-blacklist-extra", pkgver:"0.3.3+0.4-0ubuntu0.7.04.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openssl-blacklist", pkgver:"0.3.3+0.4-0ubuntu0.7.10.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openssl-blacklist-extra", pkgver:"0.3.3+0.4-0ubuntu0.7.10.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openssl-blacklist", pkgver:"0.3.3+0.4-0ubuntu0.8.04.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openssl-blacklist-extra", pkgver:"0.3.3+0.4-0ubuntu0.8.04.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl-blacklist / openssl-blacklist-extra");
}
