#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1049-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52526);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2010-1585", "CVE-2011-0051", "CVE-2011-0053", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056", "CVE-2011-0057", "CVE-2011-0058", "CVE-2011-0059", "CVE-2011-0061", "CVE-2011-0062");
  script_bugtraq_id(46647, 46648, 46650, 46651, 46660, 46661, 46663);
  script_xref(name:"USN", value:"1049-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : firefox, firefox-{3.0,3.5}, xulrunner-1.9.2 vulnerabilities (USN-1049-1)");
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
"Jesse Ruderman, Igor Bukanov, Olli Pettay, Gary Kwong, Jeff Walden,
Henry Sivonen, Martijn Wargers, David Baron and Marcia Knous
discovered several memory issues in the browser engine. An attacker
could exploit these to crash the browser or possibly run arbitrary
code as the user invoking the program. (CVE-2011-0053, CVE-2011-0062)

Zach Hoffman discovered that a recursive call to eval() wrapped in a
try/catch statement places the browser into a inconsistent state. An
attacker could exploit this to force a user to accept any dialog.
(CVE-2011-0051)

It was discovered that memory was used after being freed in a method
used by JSON.stringify. An attacker could exploit this to crash the
browser or possibly run arbitrary code as the user invoking the
program. (CVE-2011-0055)

Christian Holler discovered multiple buffer overflows in the
JavaScript engine. An attacker could exploit these to crash the
browser or possibly run arbitrary code as the user invoking the
program. (CVE-2011-0054, CVE-2011-0056)

Daniel Kozlowski discovered that a JavaScript Worker kept a reference
to memory after it was freed. An attacker could exploit this to crash
the browser or possibly run arbitrary code as the user invoking the
program. (CVE-2011-0057)

Alex Miller discovered a buffer overflow in the browser rendering
engine. An attacker could exploit this to crash the browser or
possibly run arbitrary code as the user invoking the program.
(CVE-2011-0058)

Roberto Suggi Liverani discovered a possible issue with unsafe
JavaScript execution in chrome documents. A malicious extension could
exploit this to execute arbitrary code with chrome privlieges.
(CVE-2010-1585)

Jordi Chancel discovered a buffer overlow in the JPEG decoding engine.
An attacker could exploit this to crash the browser or possibly run
arbitrary code as the user invoking the program. (CVE-2011-0061)

Peleus Uhley discovered a CSRF vulnerability in the plugin code
related to 307 redirects. This could allow custom headers to be
forwarded across origins. (CVE-2011-0059).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.0-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.1-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.5-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-2-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-2-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-2-libthai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-venkman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.1-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.1-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.5-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.5-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-gnome-support-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-libthai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-mozsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.2-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.2-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.2-testsuite-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/03");
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

if (ubuntu_check(osver:"8.04", pkgname:"abrowser", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"abrowser-branding", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0-dev", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0-gnome-support", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-branding", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-dbg", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-dev", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-gnome-support", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-gnome-support-dbg", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso-dev", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso-gnome-support", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-libthai", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk-dev", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk-gnome-support", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9.2-dbg", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9.2-dev", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9.2-gnome-support", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9.2-testsuite", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9.2-testsuite-dev", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-dev", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.0", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.0-branding", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.1", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.1-branding", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.5", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.5-branding", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-branding", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-2", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-2-dbg", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-2-dev", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-2-dom-inspector", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-2-gnome-support", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-2-libthai", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-branding", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-dev", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-dom-inspector", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-gnome-support", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-venkman", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1-branding", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1-dbg", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1-dev", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1-gnome-support", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5-branding", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5-dbg", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5-dev", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5-gnome-support", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-branding", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-dbg", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-dev", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-dom-inspector", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-gnome-support", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-gnome-support-dbg", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.2-dbg", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.2-dev", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.2-gnome-support", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.2-testsuite", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.2-testsuite-dev", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-dev", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"abrowser", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"abrowser-3.5", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"abrowser-3.5-branding", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"abrowser-branding", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-2", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-2-dbg", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-2-dev", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-2-dom-inspector", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-2-gnome-support", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-2-libthai", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-3.0", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-3.0-dev", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-3.0-gnome-support", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-3.5", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-3.5-branding", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-3.5-dbg", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-3.5-dev", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-3.5-gnome-support", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-branding", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-dbg", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-dev", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-gnome-support", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-gnome-support-dbg", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox-mozsymbols", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9.2-dbg", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9.2-dev", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9.2-gnome-support", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9.2-testsuite", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9.2-testsuite-dev", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-dev", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"abrowser", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"abrowser-branding", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"firefox", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"firefox-branding", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"firefox-dbg", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"firefox-gnome-support", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"firefox-gnome-support-dbg", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"firefox-mozsymbols", pkgver:"3.6.14+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-1.9.2-dbg", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-1.9.2-dev", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-1.9.2-gnome-support", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-1.9.2-testsuite", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-1.9.2-testsuite-dev", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-dev", pkgver:"1.9.2.14+build3+nobinonly-0ubuntu0.10.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abrowser / abrowser-3.0 / abrowser-3.0-branding / abrowser-3.1 / etc");
}
