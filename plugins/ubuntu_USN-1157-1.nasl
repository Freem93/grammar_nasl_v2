#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1157-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55408);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/26 16:14:08 $");

  script_cve_id("CVE-2011-2366", "CVE-2011-2367", "CVE-2011-2368", "CVE-2011-2369", "CVE-2011-2370", "CVE-2011-2371", "CVE-2011-2373", "CVE-2011-2374", "CVE-2011-2375", "CVE-2011-2377");
  script_xref(name:"USN", value:"1157-1");

  script_name(english:"Ubuntu 11.04 : firefox vulnerabilities (USN-1157-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bob Clary, Kevin Brosnan, Gary Kwong, Jesse Ruderman, Christian
Biesinger, Bas Schouten, Igor Bukanov, Bill McCloskey, Olli Pettay,
Daniel Veditz and Marcia Knous discovered multiple memory
vulnerabilities in the browser rendering engine. An attacker could
possibly execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2011-2374, CVE-2011-2375)

Martin Barbella discovered that under certain conditions, viewing a
XUL document while JavaScript was disabled caused deleted memory to be
accessed. An attacker could potentially use this to crash Firefox or
execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2011-2373)

Jordi Chancel discovered a vulnerability on multipart/x-mixed-replace
images due to memory corruption. An attacker could potentially use
this to crash Firefox or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2011-2377)

Chris Rohlf and Yan Ivnitskiy discovered an integer overflow
vulnerability in JavaScript Arrays. An attacker could potentially use
this to execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2011-2371)

It was discovered that Firefox's WebGL textures did not honor
same-origin policy. If a user were tricked into viewing a malicious
site, an attacker could potentially view image data from a different
site. (CVE-2011-2366)

Christoph Diehl discovered an out-of-bounds read vulnerability in
WebGL code. An attacker could potentially read data that other
processes had stored in the GPU. (CVE-2011-2367)

Christoph Diehl discovered an invalid write vulnerability in WebGL
code. An attacker could potentially use this to execute arbitrary code
with the privileges of the user invoking Firefox. (CVE-2011-2368)

It was discovered that an unauthorized site could trigger an
installation dialog for addons and themes. If a user were tricked into
viewing a malicious site, an attacker could possibly trick the user
into installing a malicious addon or theme. (CVE-2011-2370)

Mario Heiderich discovered a vulnerability in displaying decoded
HTML-encoded entities inside SVG elements. An attacker could utilize
this to perform cross-site scripting attacks. (CVE-2011-2369).

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/23");
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
if (! ereg(pattern:"^(11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"11.04", pkgname:"firefox", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.1")) flag++;

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
