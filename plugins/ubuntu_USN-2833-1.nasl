#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2833-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87406);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/05/24 17:52:28 $");

  script_cve_id("CVE-2015-7201", "CVE-2015-7202", "CVE-2015-7203", "CVE-2015-7204", "CVE-2015-7205", "CVE-2015-7207", "CVE-2015-7208", "CVE-2015-7210", "CVE-2015-7211", "CVE-2015-7212", "CVE-2015-7213", "CVE-2015-7214", "CVE-2015-7215", "CVE-2015-7216", "CVE-2015-7217", "CVE-2015-7218", "CVE-2015-7219", "CVE-2015-7220", "CVE-2015-7221", "CVE-2015-7222", "CVE-2015-7223");
  script_osvdb_id(125392, 126813, 126814, 128372, 131845, 131846, 131847, 131848, 131849, 131850, 131851, 131852, 131853, 131854, 131855, 131856, 131857, 131858, 131859, 131860, 131861, 131863, 131864, 131865, 131866, 131867, 131868, 131869, 131870, 131871, 131872, 131873, 131874, 131875, 131902, 131903);
  script_xref(name:"USN", value:"2833-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.04 / 15.10 : firefox vulnerabilities (USN-2833-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Andrei Vaida, Jesse Ruderman, Bob Clary, Christian Holler, Jesse
Ruderman, Eric Rahm, Robert Kaiser, Harald Kirschner, and Michael
Henretty discovered multiple memory safety issues in Firefox. If a
user were tricked in to opening a specially crafted website, an
attacker could potentially exploit these to cause a denial of service
via application crash, or execute arbitrary code with the privileges
of the user invoking Firefox. (CVE-2015-7201, CVE-2015-7202)

Ronald Crane discovered three buffer overflows through code
inspection. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial
of service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-7203,
CVE-2015-7220, CVE-2015-7221)

Cajus Pollmeier discovered a crash during JavaScript variable
assignments in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2015-7204)

Ronald Crane discovered a buffer overflow through code inspection. If
a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via application crash, or execute arbitrary code with the privileges
of the user invoking Firefox. (CVE-2015-7205)

It was discovered that it is possible to read cross-origin URLs
following a redirect if performance.getEntries() is used with an
iframe to host a page. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to bypass same-origin restrictions. (CVE-2015-7207)

It was discovered that Firefox allows for control characters to be set
in cookies. An attacker could potentially exploit this to conduct
cookie injection attacks on some web servers. (CVE-2015-7208)

Looben Yang discovered a use-after-free in WebRTC when closing
channels in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2015-7210)

Abdulrahman Alqabandi discovered that hash symbol is incorrectly
handled when parsing data: URLs. An attacker could potentially exploit
this to conduct URL spoofing attacks. (CVE-2015-7211)

Abhishek Arya discovered an integer overflow when allocating large
textures. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-7212)

Ronald Crane dicovered an integer overflow when processing MP4 format
video in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2015-7213)

Tsubasa Iinuma discovered a way to bypass same-origin restrictions
using data: and view-source: URLs. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to obtain sensitive information and read local files.
(CVE-2015-7214)

Masato Kinugawa discovered a cross-origin information leak in error
events in web workers. An attacker could potentially exploit this to
obtain sensitive information. (CVE-2015-7215)

Gustavo Grieco discovered that the file chooser crashed on malformed
images due to flaws in the Jasper library. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service. (CVE-2015-7216,
CVE-2015-7217)

Stuart Larsen discoverd two integer underflows when handling malformed
HTTP/2 frames in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit these to cause a denial of service via application crash.
(CVE-2015-7218, CVE-2015-7219)

Gerald Squelart discovered an integer underflow in the libstagefright
library when parsing MP4 format video in some circumstances. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2015-7222)

Kris Maglione discovered a mechanism where web content could use
WebExtension APIs to execute code with the privileges of a particular
WebExtension. If a user were tricked in to opening a specially crafted
website with a vulnerable extension installed, an attacker could
potentially exploit this to obtain sensitive information or conduct
cross-site scripting (XSS) attacks. (CVE-2015-7223).

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
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"43.0+build1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"43.0+build1-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"firefox", pkgver:"43.0+build1-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"firefox", pkgver:"43.0+build1-0ubuntu0.15.10.1")) flag++;

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
