#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-930-4. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47824);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2008-5913", "CVE-2010-0654", "CVE-2010-1121", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202", "CVE-2010-1203", "CVE-2010-1205", "CVE-2010-1206", "CVE-2010-1207", "CVE-2010-1208", "CVE-2010-1209", "CVE-2010-1210", "CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1213", "CVE-2010-1214", "CVE-2010-1215", "CVE-2010-2751", "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754");
  script_xref(name:"USN", value:"930-4");

  script_name(english:"Ubuntu 9.04 / 9.10 : firefox-3.0, firefox-3.5, xulrunner-1.9.2 vulnerabilities (USN-930-4)");
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
"USN-930-1 fixed vulnerabilities in Firefox and Xulrunner. This update
provides the corresponding updates for Ubuntu 9.04 and 9.10, along
with additional updates affecting Firefox 3.6.6.

Several flaws were discovered in the browser engine of Firefox. If a
user were tricked into viewing a malicious site, a remote attacker
could use this to crash the browser or possibly run arbitrary code as
the user invoking the program. (CVE-2010-1208, CVE-2010-1209,
CVE-2010-1211, CVE-2010-1212)

An integer overflow was discovered in how Firefox processed plugin
parameters. An attacker could exploit this to crash the browser or
possibly run arbitrary code as the user invoking the program.
(CVE-2010-1214)

A flaw was discovered in the Firefox JavaScript engine. If a user were
tricked into viewing a malicious site, a remote attacker code execute
arbitrary JavaScript with chrome privileges. (CVE-2010-1215)

An integer overflow was discovered in how Firefox processed CSS
values. An attacker could exploit this to crash the browser or
possibly run arbitrary code as the user invoking the program.
(CVE-2010-2752)

An integer overflow was discovered in how Firefox interpreted the XUL
<tree> element. If a user were tricked into viewing a malicious site,
a remote attacker could use this to crash the browser or possibly run
arbitrary code as the user invoking the program. (CVE-2010-2753)

Aki Helin discovered that libpng did not properly handle certain
malformed PNG images. If a user were tricked into opening a crafted
PNG file, an attacker could cause a denial of service or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2010-1205)

Yosuke Hasegawa and Vladimir Vukicevic discovered that the same-origin
check in Firefox could be bypassed by utilizing the importScripts Web
Worker method. If a user were tricked into viewing a malicious
website, an attacker could exploit this to read data from other
domains. (CVE-2010-1213, CVE-2010-1207)

O. Andersen that Firefox did not properly map undefined positions
within certain 8 bit encodings. An attacker could utilize this to
perform cross-site scripting attacks. (CVE-2010-1210)

Michal Zalewski discovered flaws in how Firefox processed the HTTP 204
(no content) code. An attacker could exploit this to spoof the
location bar, such as in a phishing attack. (CVE-2010-1206)

Jordi Chancel discovered that Firefox did not properly handle when a
server responds to an HTTPS request with plaintext and then processes
JavaScript history events. An attacker could exploit this to spoof the
location bar, such as in a phishing attack. (CVE-2010-2751)

Chris Evans discovered that Firefox did not properly process improper
CSS selectors. If a user were tricked into viewing a malicious
website, an attacker could exploit this to read data from other
domains. (CVE-2010-0654)

Soroush Dalili discovered that Firefox did not properly handle script
error output. An attacker could use this to access URL parameters from
other domains. (CVE-2010-2754)

If was discovered that Firefox could be made to access freed memory.
If a user were tricked into viewing a malicious site, a remote
attacker could cause a denial of service or possibly execute arbitrary
code with the privileges of the user invoking the program.
(CVE-2010-1121)

Several flaws were discovered in the browser engine of
Firefox. If a user were tricked into viewing a malicious
site, a remote attacker could cause a denial of service or
possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2010-1200, CVE-2010-1201,
CVE-2010-1202, CVE-2010-1203)

A flaw was discovered in the way plugin instances
interacted. An attacker could potentially exploit this and
use one plugin to access freed memory from a second plugin
to execute arbitrary code with the privileges of the user
invoking the program. (CVE-2010-1198)

An integer overflow was discovered in Firefox. If a user
were tricked into viewing a malicious site, an attacker
could overflow a buffer and cause a denial of service or
possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2010-1196)

Martin Barbella discovered an integer overflow in an XSLT
node sorting routine. An attacker could exploit this to
overflow a buffer and cause a denial of service or possibly
execute arbitrary code with the privileges of the user
invoking the program. (CVE-2010-1199)

Michal Zalewski discovered that the focus behavior of
Firefox could be subverted. If a user were tricked into
viewing a malicious site, a remote attacker could use this
to capture keystrokes. (CVE-2010-1125)

Ilja van Sprundel discovered that the 'Content-Disposition:
attachment' HTTP header was ignored when 'Content-Type:
multipart' was also present. Under certain circumstances,
this could potentially lead to cross-site scripting attacks.
(CVE-2010-1197)

Amit Klein discovered that Firefox did not seed its random
number generator often enough. An attacker could exploit
this to identify and track users across different websites.
(CVE-2008-5913).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.0-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.1-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.5-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-libthai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.04", pkgname:"abrowser", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"abrowser-3.0-branding", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-3.0", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-3.0-branding", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-3.0-dev", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-3.0-gnome-support", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-dev", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-gnome-support", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-granparadiso", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-granparadiso-dev", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-granparadiso-gnome-support", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-libthai", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-trunk", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-trunk-dev", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-trunk-gnome-support", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.7+build2+nobinonly-0ubuntu0.9.04.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xulrunner-dev", pkgver:"1.9.2.7+build2+nobinonly-0ubuntu0.9.04.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.0", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.0-branding", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.1", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.1-branding", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.5", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"abrowser-3.5-branding", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-branding", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-dev", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-dom-inspector", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-gnome-support", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.0-venkman", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1-branding", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1-dbg", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1-dev", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.1-gnome-support", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5-branding", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5-dbg", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5-dev", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-3.5-gnome-support", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-dom-inspector", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox-gnome-support", pkgver:"3.6.7+build2+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.7+build2+nobinonly-0ubuntu0.9.10.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-dev", pkgver:"1.9.2.7+build2+nobinonly-0ubuntu0.9.10.2")) flag++;

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
