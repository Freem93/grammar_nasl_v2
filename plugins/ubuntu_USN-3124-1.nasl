#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3124-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95025);
  script_version("$Revision: 3.5 $");
  script_cvs_date("$Date: 2016/12/07 21:18:29 $");

  script_cve_id("CVE-2016-5289", "CVE-2016-5290", "CVE-2016-5291", "CVE-2016-5292", "CVE-2016-5296", "CVE-2016-5297", "CVE-2016-9063", "CVE-2016-9064", "CVE-2016-9066", "CVE-2016-9067", "CVE-2016-9068", "CVE-2016-9069", "CVE-2016-9070", "CVE-2016-9071", "CVE-2016-9073", "CVE-2016-9075", "CVE-2016-9076", "CVE-2016-9077");
  script_osvdb_id(147338, 147339, 147342, 147343, 147345, 147346, 147347, 147348, 147350, 147351, 147352, 147360, 147361, 147363, 147364, 147365, 147366, 147367, 147368, 147369, 147370, 147371, 147372, 147373, 147374, 147375, 147376, 147377, 147378, 147379, 147380, 147381, 147382, 147383, 147384, 147385, 147386, 147387);
  script_xref(name:"USN", value:"3124-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 : firefox vulnerabilities (USN-3124-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Christian Holler, Andrew McCreight, Dan Minor, Tyson Smith, Jon
Coppeard, Jan-Ivar Bruaroey, Jesse Ruderman, Markus Stange, Olli
Pettay, Ehsan Akhgari, Gary Kwong, Tooru Fujisawa, and Randell Jesup
discovered multiple memory safety issues in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-5289, CVE-2016-5290)

A same-origin policy bypass was discovered with local HTML files in
some circumstances. An attacker could potentially exploit this to
obtain sensitive information. (CVE-2016-5291)

A crash was discovered when parsing URLs in some circumstances. If a
user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to execute arbitrary code.
(CVE-2016-5292)

A heap buffer-overflow was discovered in Cairo when processing SVG
content. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via application crash, or execute arbitrary code.
(CVE-2016-5296)

An error was discovered in argument length checking in JavaScript. If
a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via application crash, or execute arbitrary code. (CVE-2016-5297)

An integer overflow was discovered in the Expat library. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via
application crash. (CVE-2016-9063)

It was discovered that addon updates failed to verify that the addon
ID inside the signed package matched the ID of the addon being
updated. An attacker that could perform a man-in-the-middle (MITM)
attack could potentially exploit this to provide malicious addon
updates. (CVE-2016-9064)

A buffer overflow was discovered in nsScriptLoadHandler. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code. (CVE-2016-9066)

2 use-after-free bugs were discovered during DOM operations in some
circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these to cause
a denial of service via application crash, or execute arbitrary code.
(CVE-2016-9067, CVE-2016-9069)

A heap use-after-free was discovered during web animations in some
circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code.
(CVE-2016-9068)

It was discovered that a page loaded in to the sidebar through a
bookmark could reference a privileged chrome window. An attacker could
potentially exploit this to bypass same origin restrictions.
(CVE-2016-9070)

An issue was discovered with Content Security Policy (CSP) in
combination with HTTP to HTTPS redirection. An attacker could
potentially exploit this to verify whether a site is within the user's
browsing history. (CVE-2016-9071)

An issue was discovered with the windows.create() WebExtensions API.
If a user were tricked in to installing a malicious extension, an
attacker could potentially exploit this to escape the WebExtensions
sandbox. (CVE-2016-9073)

It was discovered that WebExtensions can use the mozAddonManager API.
An attacker could potentially exploit this to install additional
extensions without user permission. (CVE-2016-9075)

It was discovered that <select> element dropdown menus can cover
location bar content when e10s is enabled. An attacker could
potentially exploit this to conduct UI spoofing attacks.
(CVE-2016-9076)

It was discovered that canvas allows the use of the feDisplacementMap
filter on cross-origin images. An attacker could potentially exploit
this to conduct timing attacks. (CVE-2016-9077).

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
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/21");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"50.0+build2-0ubuntu0.12.04.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"50.0+build2-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"firefox", pkgver:"50.0+build2-0ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"firefox", pkgver:"50.0+build2-0ubuntu0.16.10.2")) flag++;

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
