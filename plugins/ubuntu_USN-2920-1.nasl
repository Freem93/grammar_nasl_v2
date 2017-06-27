#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2920-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89865);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/01 20:56:53 $");

  script_cve_id("CVE-2016-1630", "CVE-2016-1631", "CVE-2016-1633", "CVE-2016-1634", "CVE-2016-1636", "CVE-2016-1637", "CVE-2016-1641", "CVE-2016-1642", "CVE-2016-1643", "CVE-2016-1644", "CVE-2016-2843", "CVE-2016-2844", "CVE-2016-2845");
  script_osvdb_id(135241, 135242, 135244, 135245, 135247, 135248, 135252, 135287, 135458, 135460, 135461, 135462, 135463, 135470, 135619, 135649, 135650);
  script_xref(name:"USN", value:"2920-1");

  script_name(english:"Ubuntu 14.04 LTS / 15.10 : oxide-qt vulnerabilities (USN-2920-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the ContainerNode::parserRemoveChild function
in Blink mishandled widget updates in some circumstances. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to bypass same-origin restrictions.
(CVE-2016-1630)

It was discovered that the PPB_Flash_MessageLoop_Impl::InternalRun
function in Chromium mishandled nested message loops. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to bypass same-origin restrictions.
(CVE-2016-1631)

Multiple use-after-frees were discovered in Blink. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via renderer
crash or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2016-1633, CVE-2016-1634, CVE-2016-1644)

It was discovered that the PendingScript::notifyFinished function in
Blink relied on memory-cache information about integrity-check
occurrences instead of integrity-check successes. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to bypass Subresource Integrity (SRI)
protections. (CVE-2016-1636)

It was discovered that the SkATan2_255 function in Skia mishandled
arctangent calculations. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to obtain sensitive information. (CVE-2016-1637)

A use-after-free was discovered in Chromium. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2016-1641)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2016-1642)

A type-confusion bug was discovered in Blink. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via renderer
crash or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2016-1643)

Multiple security issues were discovered in V8. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via renderer crash or execute arbitrary code with the
privileges of the sandboxed render process. (CVE-2016-2843)

An invalid cast was discovered in Blink. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash or
execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2016-2844)

It was discovered that the Content Security Policy (CSP)
implementation in Blink did not ignore a URL's path component in the
case of a ServiceWorker fetch. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to obtain sensitive information. (CVE-2016-2845).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected liboxideqtcore0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/11");
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
if (! ereg(pattern:"^(14\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.13.6-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"liboxideqtcore0", pkgver:"1.13.6-0ubuntu0.15.10.1")) flag++;

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
