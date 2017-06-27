#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1401-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58397);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/25 16:11:46 $");

  script_cve_id("CVE-2011-3658", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457", "CVE-2012-0458", "CVE-2012-0461", "CVE-2012-0464");
  script_bugtraq_id(51138, 52458, 52459, 52460, 52461, 52464, 52465);
  script_osvdb_id(77953);
  script_xref(name:"USN", value:"1401-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 : xulrunner-1.9.2 vulnerabilities (USN-1401-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that a flaw in the Mozilla SVG implementation could
result in an out-of-bounds memory access if SVG elements were removed
during a DOMAttrModified event handler. If the user were tricked into
opening a specially crafted page, an attacker could exploit this to
cause a denial of service via application crash. (CVE-2011-3658)

Atte Kettunen discovered a use-after-free vulnerability in the Gecko
Rendering Engine's handling of SVG animations. An attacker could
potentially exploit this to execute arbitrary code with the privileges
of the user invoking the Xulrunner based application. (CVE-2012-0457)

Atte Kettunen discovered an out of bounds read vulnerability in the
Gecko Rendering Engine's handling of SVG Filters. An attacker could
potentially exploit this to make data from the user's memory
accessible to the page content. (CVE-2012-0456)

Soroush Dalili discovered that the Gecko Rendering Engine did not
adequately protect against dropping JavaScript links onto a frame. A
remote attacker could, through cross-site scripting (XSS), exploit
this to modify the contents of the frame or steal confidential data.
(CVE-2012-0455)

Mariusz Mlynski discovered that the Home button accepted JavaScript
links to set the browser Home page. An attacker could use this
vulnerability to get the script URL loaded in the privileged
about:sessionrestore context. (CVE-2012-0458)

Bob Clary, Vincenzo Iozzo, and Willem Pinckaers discovered memory
safety issues affecting Firefox. If the user were tricked into opening
a specially crafted page, an attacker could exploit these to cause a
denial of service via application crash, or potentially execute code
with the privileges of the user invoking Firefox. (CVE-2012-0461,
CVE-2012-0464).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xulrunner-1.9.2 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox nsSVGValue Out-of-Bounds Access Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2016 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.28+build1+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.28+build1+nobinonly-0ubuntu0.10.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xulrunner-1.9.2");
}
