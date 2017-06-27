#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2936-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91255);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/12/01 20:56:53 $");

  script_cve_id("CVE-2016-2804", "CVE-2016-2806", "CVE-2016-2807", "CVE-2016-2808", "CVE-2016-2811", "CVE-2016-2812", "CVE-2016-2814", "CVE-2016-2816", "CVE-2016-2817", "CVE-2016-2820");
  script_osvdb_id(137609, 137610, 137611, 137613, 137614, 137615, 137616, 137617, 137618, 137619, 137620, 137621, 137622, 137623, 137624, 137625, 137626, 137627, 137628, 137629, 137630, 137631, 137632, 137633, 137636, 137637, 137639, 137640, 137641, 137642, 137643);
  script_xref(name:"USN", value:"2936-3");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 / 16.04 LTS : firefox regression (USN-2936-3)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-2936-1 fixed vulnerabilities in Firefox. The update caused an
issue where a device update POST request was sent every time
about:preferences#sync was shown. This update fixes the problem.

We apologize for the inconvenience.

Christian Holler, Tyson Smith, Phil Ringalda, Gary Kwong, Jesse
Ruderman, Mats Palmgren, Carsten Book, Boris Zbarsky, David Bolter,
Randell Jesup, Andrew McCreight, and Steve Fink discovered multiple
memory safety issues in Firefox. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit
these to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2016-2804, CVE-2016-2806, CVE-2016-2807)

An invalid write was discovered when using the JavaScript
.watch() method in some circumstances. If a user were
tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox.
(CVE-2016-2808)

Looben Yang discovered a use-after-free and buffer overflow
in service workers. If a user were tricked in to opening a
specially crafted website, an attacker could potentially
exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2016-2811, CVE-2016-2812)

Sascha Just discovered a buffer overflow in libstagefright
in some circumstances. If a user were tricked in to opening
a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2016-2814)

Muneaki Nishimura discovered that CSP is not applied
correctly to web content sent with the
multipart/x-mixed-replace MIME type. An attacker could
potentially exploit this to conduct cross-site scripting
(XSS) attacks when they would otherwise be prevented.
(CVE-2016-2816)

Muneaki Nishimura discovered that the chrome.tabs.update API
for web extensions allows for navigation to javascript:
URLs. A malicious extension could potentially exploit this
to conduct cross-site scripting (XSS) attacks.
(CVE-2016-2817)

Mark Goodwin discovered that about:healthreport accepts
certain events from any content present in the remote-report
iframe. If another vulnerability allowed the injection of
web content in the remote-report iframe, an attacker could
potentially exploit this to change the user's sharing
preferences. (CVE-2016-2820).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");
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

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"46.0.1+build1-0ubuntu0.12.04.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"46.0.1+build1-0ubuntu0.14.04.3")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"firefox", pkgver:"46.0.1+build1-0ubuntu0.15.10.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"firefox", pkgver:"46.0.1+build1-0ubuntu0.16.04.2")) flag++;

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
