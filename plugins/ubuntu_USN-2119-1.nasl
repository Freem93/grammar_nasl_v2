#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2119-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72599);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/26 16:22:49 $");

  script_cve_id("CVE-2013-6674", "CVE-2014-1477", "CVE-2014-1479", "CVE-2014-1481", "CVE-2014-1482", "CVE-2014-1486", "CVE-2014-1487", "CVE-2014-1490", "CVE-2014-1491");
  script_bugtraq_id(65158, 65317, 65320, 65326, 65328, 65330, 65332, 65334, 65335);
  script_osvdb_id(102566, 102863, 102864, 102866, 102868, 102872, 102873, 102876, 102877, 107380, 107381, 107382, 107383, 107384, 107385, 107386, 107387, 107388, 107390);
  script_xref(name:"USN", value:"2119-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.10 : thunderbird vulnerabilities (USN-2119-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Christian Holler, Terrence Cole, Jesse Ruderman, Gary Kwong, Eric
Rescorla, Jonathan Kew, Dan Gohman, Ryan VanderMeulen and Sotaro Ikeda
discovered multiple memory safety issues in Thunderbird. If a user
were tricked in to opening a specially crafted message with scripting
enabled, an attacker could potentially exploit these to cause a denial
of service via application crash, or execute arbitrary code with the
privileges of the user invoking Thunderbird. (CVE-2014-1477)

Cody Crews discovered a method to bypass System Only Wrappers. If a
user had enabled scripting, an attacker could potentially exploit this
to steal confidential data or execute code with the privileges of the
user invoking Thunderbird. (CVE-2014-1479)

Fredrik Lonnqvist discovered a use-after-free in Thunderbird. If a
user had enabled scripting, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute
arbitrary code with the priviliges of the user invoking Thunderbird.
(CVE-2014-1482)

Arthur Gerkis discovered a use-after-free in Thunderbird. If a user
had enabled scripting, an attacker could potentially exploit this to
cause a denial of service via application crash, or execute arbitrary
code with the priviliges of the user invoking Thunderbird.
(CVE-2014-1486)

Masato Kinugawa discovered a cross-origin information leak in web
worker error messages. If a user had enabled scripting, an attacker
could potentially exploit this to steal confidential information.
(CVE-2014-1487)

Several issues were discovered with ticket handling in NSS. An
attacker could potentially exploit these to cause a denial of service
or bypass cryptographic protection mechanisms. (CVE-2014-1490,
CVE-2014-1491)

Boris Zbarsky discovered that security restrictions on window objects
could be bypassed under certain circumstances. (CVE-2014-1481)

Fabian Cuchietti and Ateeq ur Rehman Khan discovered that it was
possible to bypass JavaScript execution restrictions when replying to
or forwarding mail messages in certain circumstances. An attacker
could potentially exploit this to steal confidential information or
modify message content. (CVE-2013-6674).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/20");
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
if (! ereg(pattern:"^(12\.04|12\.10|13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10 / 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"thunderbird", pkgver:"1:24.3.0+build2-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"thunderbird", pkgver:"1:24.3.0+build2-0ubuntu0.12.10.1")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"thunderbird", pkgver:"1:24.3.0+build2-0ubuntu0.13.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
