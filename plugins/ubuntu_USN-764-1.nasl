#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-764-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36228);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2009-0652", "CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1310", "CVE-2009-1311", "CVE-2009-1312");
  script_xref(name:"USN", value:"764-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 : firefox-3.0, xulrunner-1.9 vulnerabilities (USN-764-1)");
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
"Several flaws were discovered in the browser engine. If a user were
tricked into viewing a malicious website, a remote attacker could
cause a denial of service or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2009-1302,
CVE-2009-1303, CVE-2009-1304, CVE-2009-1305)

It was discovered that Firefox displayed certain Unicode characters
which could be visually confused with punctuation in valid web
addresses in the location bar. An attacker could exploit this to spoof
the location bar, such as in a phishing attack. (CVE-2009-0652)

Several flaws were discovered in the way Firefox processed malformed
URI schemes. If a user were tricked into viewing a malicious website,
a remote attacker could execute arbitrary JavaScript or steal private
data. (CVE-2009-1306, CVE-2009-1307, CVE-2009-1309, CVE-2009-1310,
CVE-2009-1312)

Cefn Hoile discovered Firefox did not adequately protect against
embedded third-party stylesheets. An attacker could exploit this to
perform script injection attacks using XBL bindings. (CVE-2009-1308)

Paolo Amadini discovered that Firefox would submit POST data when
reloading an inner frame of a web page. If a user were tricked into
viewing a malicious website, a remote attacker could steal private
data. (CVE-2009-1311).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 79, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-3.0-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-venkman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-libthai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk-venkman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9-venkman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"firefox", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0-dev", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0-dom-inspector", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0-gnome-support", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0-venkman", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-dev", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-dom-inspector", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-gnome-support", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso-dev", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso-dom-inspector", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso-gnome-support", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-libthai", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk-dev", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk-dom-inspector", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk-gnome-support", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk-venkman", pkgver:"3.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9", pkgver:"1.9.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9-dev", pkgver:"1.9.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9-dom-inspector", pkgver:"1.9.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9-gnome-support", pkgver:"1.9.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9-venkman", pkgver:"1.9.0.9+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"abrowser", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"abrowser-3.0-branding", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-3.0", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-3.0-branding", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-3.0-dev", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-3.0-dom-inspector", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-3.0-gnome-support", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-3.0-venkman", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-dev", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-dom-inspector", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-gnome-support", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-granparadiso", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-granparadiso-dev", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-granparadiso-dom-inspector", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-granparadiso-gnome-support", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-libthai", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-trunk", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-trunk-dev", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-trunk-dom-inspector", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-trunk-gnome-support", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"firefox-trunk-venkman", pkgver:"3.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"xulrunner-1.9", pkgver:"1.9.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"xulrunner-1.9-dev", pkgver:"1.9.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"xulrunner-1.9-dom-inspector", pkgver:"1.9.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"xulrunner-1.9-gnome-support", pkgver:"1.9.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"xulrunner-1.9-venkman", pkgver:"1.9.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"xulrunner-dev", pkgver:"1.9.0.9+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"abrowser", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"abrowser-3.0-branding", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-3.0", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-3.0-branding", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-3.0-dev", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-3.0-dom-inspector", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-3.0-gnome-support", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-3.0-venkman", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-dev", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-dom-inspector", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-gnome-support", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-granparadiso", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-granparadiso-dev", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-granparadiso-dom-inspector", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-granparadiso-gnome-support", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-libthai", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-trunk", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-trunk-dev", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-trunk-dom-inspector", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-trunk-gnome-support", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"firefox-trunk-venkman", pkgver:"3.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xulrunner-1.9", pkgver:"1.9.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xulrunner-1.9-dev", pkgver:"1.9.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xulrunner-1.9-dom-inspector", pkgver:"1.9.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xulrunner-1.9-gnome-support", pkgver:"1.9.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xulrunner-1.9-venkman", pkgver:"1.9.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"xulrunner-dev", pkgver:"1.9.0.9+nobinonly-0ubuntu0.9.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abrowser / abrowser-3.0-branding / firefox / firefox-3.0 / etc");
}
