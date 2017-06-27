#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2591-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83182);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2015-3143", "CVE-2015-3144", "CVE-2015-3145", "CVE-2015-3148", "CVE-2015-3153");
  script_osvdb_id(121128, 121129, 121130, 121131, 121452);
  script_xref(name:"USN", value:"2591-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 14.10 / 15.04 : curl vulnerabilities (USN-2591-1)");
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
"Paras Sethia discovered that curl could incorrectly re-use NTLM HTTP
credentials when subsequently connecting to the same host over HTTP.
(CVE-2015-3143)

Hanno Bock discovered that curl incorrectly handled zero-length host
names. If a user or automated system were tricked into using a
specially crafted host name, an attacker could possibly use this issue
to cause curl to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 14.10 and
Ubuntu 15.04. (CVE-2015-3144)

Hanno Bock discovered that curl incorrectly handled cookie path
elements. If a user or automated system were tricked into parsing a
specially crafted cookie, an attacker could possibly use this issue to
cause curl to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 14.04 LTS,
Ubuntu 14.10 and Ubuntu 15.04. (CVE-2015-3145)

Isaac Boukris discovered that when using Negotiate authenticated
connections, curl could incorrectly authenticate the entire connection
and not just specific HTTP requests. (CVE-2015-3148)

Yehezkel Horowitz and Oren Souroujon discovered that curl sent HTTP
headers both to servers and proxies by default, contrary to
expectations. This issue only affected Ubuntu 14.10 and Ubuntu 15.04.
(CVE-2015-3153).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libcurl3, libcurl3-gnutls and / or libcurl3-nss
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/01");
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

if (ubuntu_check(osver:"12.04", pkgname:"libcurl3", pkgver:"7.22.0-3ubuntu4.14")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libcurl3-gnutls", pkgver:"7.22.0-3ubuntu4.14")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libcurl3-nss", pkgver:"7.22.0-3ubuntu4.14")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libcurl3", pkgver:"7.35.0-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libcurl3-gnutls", pkgver:"7.35.0-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libcurl3-nss", pkgver:"7.35.0-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"libcurl3", pkgver:"7.37.1-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"libcurl3-gnutls", pkgver:"7.37.1-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"libcurl3-nss", pkgver:"7.37.1-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libcurl3", pkgver:"7.38.0-3ubuntu2.2")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libcurl3-gnutls", pkgver:"7.38.0-3ubuntu2.2")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libcurl3-nss", pkgver:"7.38.0-3ubuntu2.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcurl3 / libcurl3-gnutls / libcurl3-nss");
}
