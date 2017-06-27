#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2150-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73092);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/26 16:22:49 $");

  script_cve_id("CVE-2014-1493", "CVE-2014-1494", "CVE-2014-1497", "CVE-2014-1498", "CVE-2014-1499", "CVE-2014-1500", "CVE-2014-1502", "CVE-2014-1504", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514");
  script_bugtraq_id(66422, 66425);
  script_xref(name:"USN", value:"2150-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.10 : firefox vulnerabilities (USN-2150-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Benoit Jacob, Olli Pettay, Jan Varga, Jan de Mooij, Jesse Ruderman,
Dan Gohman, Christoph Diehl, Gregor Wagner, Gary Kwong, Luke Wagner,
Rob Fletcher and Makoto Kato discovered multiple memory safety issues
in Firefox. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial
of service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2014-1493,
CVE-2014-1494)

Atte Kettunen discovered an out-of-bounds read during WAV file
decoding. An attacker could potentially exploit this to cause a denial
of service via application crash. (CVE-2014-1497)

David Keeler discovered that crypto.generateCRFMRequest did not
correctly validate all arguments. An attacker could potentially
exploit this to cause a denial of service via application crash.
(CVE-2014-1498)

Ehsan Akhgari discovered that the WebRTC permission dialog can display
the wrong originating site information under some circumstances. An
attacker could potentially exploit this by tricking a user in order to
gain access to their webcam or microphone. (CVE-2014-1499)

Tim Philipp Schafers and Sebastian Neef discovered that
onbeforeunload events used with page navigations could make the
browser unresponsive in some circumstances. An attacker could
potentially exploit this to cause a denial of service. (CVE-2014-1500)

Jeff Gilbert discovered that WebGL content could manipulate content
from another sites WebGL context. An attacker could potentially
exploit this to conduct spoofing attacks. (CVE-2014-1502)

Nicolas Golubovic discovered that CSP could be bypassed for data:
documents during session restore. An attacker could potentially
exploit this to conduct cross-site scripting attacks. (CVE-2014-1504)

Robert O'Callahan discovered a mechanism for timing attacks involving
SVG filters and displacements input to feDisplacementMap. An attacker
could potentially exploit this to steal confidential information
across domains. (CVE-2014-1505)

Tyson Smith and Jesse Schwartzentruber discovered an out-of-bounds
read during polygon rendering in MathML. An attacker could potentially
exploit this to steal confidential information across domains.
(CVE-2014-1508)

John Thomson discovered a memory corruption bug in the Cairo graphics
library. If a user had a malicious extension installed, an attacker
could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2014-1509)

Mariusz Mlynski discovered that web content could open a chrome
privileged page and bypass the popup blocker in some circumstances. An
attacker could potentially exploit this to execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2014-1510,
CVE-2014-1511)

It was discovered that memory pressure during garbage collection
resulted in memory corruption in some circumstances. An attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2014-1512)

Juri Aedla discovered out-of-bounds reads and writes with
TypedArrayObject in some circumstances. An attacker could potentially
exploit this to cause a denial of service via application crash or
execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2014-1513)

George Hotz discovered an out-of-bounds write with TypedArrayObject.
An attacker could potentially exploit this to cause a denial of
service via application crash or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2014-1514).

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
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox WebIDL Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|12\.10|13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10 / 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"28.0+build2-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"firefox", pkgver:"28.0+build2-0ubuntu0.12.10.1")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"firefox", pkgver:"28.0+build2-0ubuntu0.13.10.1")) flag++;

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
