#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1306-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57458);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/25 16:11:45 $");

  script_cve_id("CVE-2011-3658", "CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3663", "CVE-2011-3665");
  script_bugtraq_id(51133, 51134, 51135, 51136, 51138);
  script_osvdb_id(77951, 77952, 77953, 77954, 77956);
  script_xref(name:"USN", value:"1306-2");

  script_name(english:"Ubuntu 11.04 / 11.10 : mozvoikko, ubufox update (USN-1306-2)");
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
"USN-1306-1 fixed vulnerabilities in Firefox. This update provides
updated Mozvoikko and ubufox packages for use with Firefox 9.

Alexandre Poirot, Chris Blizzard, Kyle Huey, Scoobidiver, Christian
Holler, David Baron, Gary Kwong, Jim Blandy, Bob Clary, Jesse
Ruderman, Marcia Knous, and Rober Longson discovered several memory
safety issues which could possibly be exploited to crash Firefox or
execute arbitrary code as the user that invoked Firefox.
(CVE-2011-3660)

Aki Helin discovered a crash in the YARR regular expression
library that could be triggered by JavaScript in web
content. (CVE-2011-3661)

It was discovered that a flaw in the Mozilla SVG
implementation could result in an out-of-bounds memory
access if SVG elements were removed during a DOMAttrModified
event handler. An attacker could potentially exploit this
vulnerability to crash Firefox. (CVE-2011-3658)

Mario Heiderich discovered it was possible to use SVG
animation accessKey events to detect key strokes even when
JavaScript was disabled. A malicious web page could
potentially exploit this to trick a user into interacting
with a prompt thinking it came from the browser in a context
where the user believed scripting was disabled.
(CVE-2011-3663)

It was discovered that it was possible to crash Firefox when
scaling an OGG <video> element to extreme sizes.
(CVE-2011-3665).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected xul-ext-mozvoikko and / or xul-ext-ubufox
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox nsSVGValue Out-of-Bounds Access Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-ubufox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/09");
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
if (! ereg(pattern:"^(11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"11.04", pkgname:"xul-ext-mozvoikko", pkgver:"1.10.0-0ubuntu0.11.04.4")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"xul-ext-ubufox", pkgver:"0.9.3-0ubuntu0.11.04.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"xul-ext-mozvoikko", pkgver:"1.10.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"xul-ext-ubufox", pkgver:"1.0.2-0ubuntu0.11.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xul-ext-mozvoikko / xul-ext-ubufox");
}
