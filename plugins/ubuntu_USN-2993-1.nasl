#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2993-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91557);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/12/01 21:07:49 $");

  script_cve_id("CVE-2016-2815", "CVE-2016-2818", "CVE-2016-2819", "CVE-2016-2821", "CVE-2016-2822", "CVE-2016-2825", "CVE-2016-2828", "CVE-2016-2829", "CVE-2016-2831", "CVE-2016-2832", "CVE-2016-2833", "CVE-2016-2834");
  script_osvdb_id(139436, 139437, 139438, 139439, 139440, 139441, 139442, 139443, 139444, 139445, 139446, 139447, 139448, 139449, 139450, 139451, 139452, 139453, 139454, 139455, 139456, 139457, 139459, 139461, 139462, 139463, 139464, 139465, 139466, 139467, 139468, 139469);
  script_xref(name:"USN", value:"2993-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 / 16.04 LTS : firefox vulnerabilities (USN-2993-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Christian Holler, Gary Kwong, Jesse Ruderman, Tyson Smith, Timothy
Nikkel, Sylvestre Ledru, Julian Seward, Olli Pettay, Karl Tomlinson,
Christoph Diehl, Julian Hector, Jan de Mooij, Mats Palmgren, and Tooru
Fujisawa discovered multiple memory safety issues in Firefox. If a
user were tricked in to opening a specially crafted website, an
attacker could potentially exploit these to cause a denial of service
via application crash, or execute arbitrary code. (CVE-2016-2815,
CVE-2016-2818)

A buffer overflow was discovered when parsing HTML5 fragments in some
circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code.
(CVE-2016-2819)

A use-after-free was discovered in contenteditable mode in some
circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code.
(CVE-2016-2821)

Jordi Chancel discovered a way to use a persistent menu within a
<select> element and place this in an arbitrary location. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to spoof the addressbar contents.
(CVE-2016-2822)

Armin Razmdjou that the location.host property can be set to an
arbitrary string after creating an invalid data: URI. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to bypass some same-origin protections.
(CVE-2016-2825)

A use-after-free was discovered when processing WebGL content in some
circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code.
(CVE-2016-2828)

Tim McCormack discovered that the permissions notification can show
the wrong icon when a page requests several permissions in quick
succession. An attacker could potentially exploit this by tricking the
user in to giving consent for access to the wrong resource.
(CVE-2016-2829)

It was discovered that a pointerlock can be created in a fullscreen
window without user consent in some circumstances, and this
pointerlock cannot be cancelled without quitting Firefox. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service or conduct
clickjacking attacks. (CVE-2016-2831)

John Schoenick discovered that CSS pseudo-classes can leak information
about plugins that are installed but disabled. An attacker could
potentially exploit this to fingerprint users. (CVE-2016-2832)

Matt Wobensmith discovered that Content Security Policy (CSP) does not
block the loading of cross-domain Java applets when specified by
policy. An attacker could potentially exploit this to bypass CSP
protections and conduct cross-site scripting (XSS) attacks.
(CVE-2016-2833)

In addition, multiple unspecified security issues were discovered in
NSS. (CVE-2016-2834).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/10");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.10|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.10 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"47.0+build3-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"47.0+build3-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"firefox", pkgver:"47.0+build3-0ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"firefox", pkgver:"47.0+build3-0ubuntu0.16.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
