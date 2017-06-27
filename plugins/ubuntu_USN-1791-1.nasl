#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1791-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65867);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/25 16:27:05 $");

  script_cve_id("CVE-2013-0788", "CVE-2013-0791", "CVE-2013-0793", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0800");
  script_bugtraq_id(58819, 58825, 58826, 58831, 58836, 58837);
  script_osvdb_id(91874, 91879, 91880, 91882, 91885, 91886);
  script_xref(name:"USN", value:"1791-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.10 / 12.04 LTS / 12.10 : thunderbird vulnerabilities (USN-1791-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Olli Pettay, Jesse Ruderman, Boris Zbarsky, Christian Holler, Milan
Sreckovic and Joe Drew discovered multiple memory safety issues
affecting Thunderbird. If the user were tricked into opening a
specially crafted message with scripting enabled, an attacker could
possibly exploit these to cause a denial of service via application
crash, or potentially execute code with the privileges of the user
invoking Thunderbird. (CVE-2013-0788)

Ambroz Bizjak discovered an out-of-bounds array read in the
CERT_DecodeCertPackage function of the Network Security Services (NSS)
libary when decoding certain certificates. An attacker could
potentially exploit this to cause a denial of service via application
crash. (CVE-2013-0791)

Mariusz Mlynski discovered that timed history navigations could be
used to load arbitrary websites with the wrong URL displayed in the
addressbar. An attacker could exploit this to conduct cross-site
scripting (XSS) or phishing attacks if scripting were enabled.
(CVE-2013-0793)

Cody Crews discovered that the cloneNode method could be used to
bypass System Only Wrappers (SOW) to clone a protected node and bypass
same-origin policy checks. If a user had enabled scripting, an
attacker could potentially exploit this to steal confidential data or
execute code with the privileges of the user invoking Thunderbird.
(CVE-2013-0795)

A crash in WebGL rendering was discovered in Thunderbird. An attacker
could potentially exploit this to execute code with the privileges of
the user invoking Thunderbird if scripting were enabled. This issue
only affects users with Intel graphics drivers. (CVE-2013-0796)

Abhishek Arya discovered an out-of-bounds write in the Cairo graphics
library. An attacker could potentially exploit this to execute code
with the privileges of the user invoking Thunderbird. (CVE-2013-0800).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|11\.10|12\.04|12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.10 / 12.04 / 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"thunderbird", pkgver:"17.0.5+build1-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"thunderbird", pkgver:"17.0.5+build1-0ubuntu0.11.10.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"thunderbird", pkgver:"17.0.5+build1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"thunderbird", pkgver:"17.0.5+build1-0ubuntu0.12.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
