#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-645-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65110);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2008-0016", "CVE-2008-3835", "CVE-2008-3836", "CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4063", "CVE-2008-4064", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4069");
  script_bugtraq_id(31346);
  script_osvdb_id(48780, 56782);
  script_xref(name:"USN", value:"645-2");

  script_name(english:"Ubuntu 6.06 LTS : firefox vulnerabilities (USN-645-2)");
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
"USN-645-1 fixed vulnerabilities in Firefox and xulrunner for Ubuntu
7.04, 7.10 and 8.04 LTS. This provides the corresponding update for
Ubuntu 6.06 LTS.

Justin Schuh, Tom Cross and Peter Williams discovered errors in the
Firefox URL parsing routines. If a user were tricked into opening a
crafted hyperlink, an attacker could overflow a stack buffer and
execute arbitrary code. (CVE-2008-0016)

It was discovered that the same-origin check in Firefox
could be bypassed. If a user were tricked into opening a
malicious website, an attacker may be able to execute
JavaScript in the context of a different website.
(CVE-2008-3835)

Several problems were discovered in the JavaScript engine.
This could allow an attacker to execute scripts from page
content with chrome privileges. (CVE-2008-3836)

Paul Nickerson discovered Firefox did not properly process
mouse click events. If a user were tricked into opening a
malicious web page, an attacker could move the content
window, which could potentially be used to force a user to
perform unintended drag and drop operations. (CVE-2008-3837)

Several problems were discovered in the browser engine. This
could allow an attacker to execute code with chrome
privileges. (CVE-2008-4058, CVE-2008-4059, CVE-2008-4060)

Drew Yao, David Maciejak and other Mozilla developers found
several problems in the browser engine of Firefox. If a user
were tricked into opening a malicious web page, an attacker
could cause a denial of service or possibly execute
arbitrary code with the privileges of the user invoking the
program. (CVE-2008-4061, CVE-2008-4062, CVE-2008-4063,
CVE-2008-4064)

Dave Reed discovered a flaw in the JavaScript parsing code
when processing certain BOM characters. An attacker could
exploit this to bypass script filters and perform cross-site
scripting attacks. (CVE-2008-4065)

Gareth Heyes discovered a flaw in the HTML parser of
Firefox. If a user were tricked into opening a malicious web
page, an attacker could bypass script filtering and perform
cross-site scripting attacks. (CVE-2008-4066)

Boris Zbarsky and Georgi Guninski independently discovered
flaws in the resource: protocol. An attacker could exploit
this to perform directory traversal, read information about
the system, and prompt the user to save information in a
file. (CVE-2008-4067, CVE-2008-4068)

Billy Hoffman discovered a problem in the XBM decoder. If a
user were tricked into opening a malicious web page or XBM
file, an attacker may be able to cause a denial of service
via application crash. (CVE-2008-4069).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(22, 79, 119, 189, 200, 264, 399);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"firefox", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dbg", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dev", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dom-inspector", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-gnome-support", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnspr-dev", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnspr4", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnss-dev", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnss3", pkgver:"1.firefox1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-firefox", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-firefox-dev", pkgver:"1.5.dfsg+1.5.0.15~prepatch080614e-0ubuntu3")) flag++;

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
