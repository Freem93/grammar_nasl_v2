#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2735-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85872);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/05/24 17:44:50 $");

  script_cve_id("CVE-2015-1291", "CVE-2015-1292", "CVE-2015-1293", "CVE-2015-1294", "CVE-2015-1299", "CVE-2015-1300", "CVE-2015-1301", "CVE-2015-1332");
  script_osvdb_id(122423, 126935, 126936, 126937, 126938, 126943, 126944, 126945, 126946, 126988, 126990, 126991, 126992, 126993, 126994, 127026, 127027, 127032, 127033, 127034, 127398);
  script_xref(name:"USN", value:"2735-1");

  script_name(english:"Ubuntu 14.04 LTS / 15.04 : oxide-qt vulnerabilities (USN-2735-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the DOM tree could be corrupted during parsing
in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to bypass same-origin restrictions or cause a denial of service.
(CVE-2015-1291)

An issue was discovered in NavigatorServiceWorker::serviceWorker in
Blink. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to bypass
same-origin restrictions. (CVE-2015-1292)

An issue was discovered in the DOM implementation in Blink. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to bypass same-origin restrictions.
(CVE-2015-1293)

A use-after-free was discovered in Skia. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash, or
execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2015-1294)

A use-after-free was discovered in the shared-timer implementation in
Blink. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via renderer crash, or execute arbitrary code with the
privileges of the sandboxed render process. (CVE-2015-1299)

It was discovered that the availability of iframe Resource Timing API
times was not properly restricted in some circumstances. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to obtain sensitive information.
(CVE-2015-1300)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1301)

A heap corruption issue was discovered in
oxide::JavaScriptDialogManager. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2015-1332).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected liboxideqtcore0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04|15\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 15.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.9.1-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"liboxideqtcore0", pkgver:"1.9.1-0ubuntu0.15.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "liboxideqtcore0");
}
