#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-398-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27984);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/27 14:21:18 $");

  script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6499", "CVE-2006-6500", "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503", "CVE-2006-6504", "CVE-2006-6506", "CVE-2006-6507");
  script_bugtraq_id(21668);
  script_osvdb_id(31339, 31340, 31341, 31342, 31343, 31344, 31345, 31346, 31347, 31348);
  script_xref(name:"USN", value:"398-1");

  script_name(english:"Ubuntu 6.10 : firefox vulnerabilities (USN-398-1)");
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
"Various flaws have been reported that allow an attacker to execute
arbitrary code with user privileges by tricking the user into opening
a malicious web page containing JavaScript or SVG. (CVE-2006-6497,
CVE-2006-6498, CVE-2006-6499, CVE-2006-6501, CVE-2006-6502,
CVE-2006-6504)

Various flaws have been reported that allow an attacker to bypass
Firefox's internal XSS protections by tricking the user into opening a
malicious web page containing JavaScript. (CVE-2006-6503,
CVE-2006-6507)

Jared Breland discovered that the 'Feed Preview' feature could leak
referrer information to remote servers. (CVE-2006-6506).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.10", pkgname:"firefox", pkgver:"2.0.0.1+0dfsg-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox-dbg", pkgver:"2.0.0.1+0dfsg-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox-dev", pkgver:"2.0.0.1+0dfsg-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox-dom-inspector", pkgver:"2.0.0.1+0dfsg-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox-gnome-support", pkgver:"2.0.0.1+0dfsg-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libnspr-dev", pkgver:"2.0.0.1+0dfsg-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libnspr4", pkgver:"2.0.0.1+0dfsg-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libnss-dev", pkgver:"2.0.0.1+0dfsg-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libnss3", pkgver:"2.0.0.1+0dfsg-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-firefox", pkgver:"2.0.0.1+0dfsg-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-firefox-dev", pkgver:"2.0.0.1+0dfsg-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-firefox-dom-inspector", pkgver:"2.0.0.1+0dfsg-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-firefox-gnome-support", pkgver:"2.0.0.1+0dfsg-0ubuntu0.6.10")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-dbg / firefox-dev / firefox-dom-inspector / etc");
}
