#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1149-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55469);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:21:16 $");

  script_cve_id("CVE-2011-0083", "CVE-2011-0085", "CVE-2011-2362", "CVE-2011-2363", "CVE-2011-2364", "CVE-2011-2365", "CVE-2011-2371", "CVE-2011-2373", "CVE-2011-2374", "CVE-2011-2376", "CVE-2011-2377");
  script_xref(name:"USN", value:"1149-2");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 : firefox regression (USN-1149-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-1149-1 fixed vulnerabilities in Firefox. Unfortunately, a
regression was introduced that prevented cookies from being stored
properly when the hostname was a single character. This update fixes
the problem. We apologize for the inconvenience.

Multiple memory vulnerabilities were discovered in the browser
rendering engine. An attacker could use these to possibly execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2011-2364, CVE-2011-2365, CVE-2011-2374, CVE-2011-2376)

Martin Barbella discovered that under certain conditions,
viewing a XUL document while JavaScript was disabled caused
deleted memory to be accessed. An attacker could potentially
use this to crash Firefox or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2011-2373)

Jordi Chancel discovered a vulnerability on
multipart/x-mixed-replace images due to memory corruption.
An attacker could potentially use this to crash Firefox or
execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2011-2377)

Chris Rohlf and Yan Ivnitskiy discovered an integer overflow
vulnerability in JavaScript Arrays. An attacker could
potentially use this to execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2011-2371)

Multiple use-after-free vulnerabilities were discovered. An
attacker could potentially use these to execute arbitrary
code with the privileges of the user invoking Firefox.
(CVE-2011-0083, CVE-2011-0085, CVE-2011-2363)

David Chan discovered that cookies did not honor same-origin
conventions. This could potentially lead to cookie data
being leaked to a third-party. (CVE-2011-2362).

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
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox Array.reduceRight() Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/30");
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
if (! ereg(pattern:"^(10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"firefox", pkgver:"3.6.18+build2+nobinonly-0ubuntu0.10.04.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"firefox", pkgver:"3.6.18+build2+nobinonly-0ubuntu0.10.10.2")) flag++;

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
