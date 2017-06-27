#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1157-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55413);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/26 16:14:08 $");

  script_cve_id("CVE-2011-2366", "CVE-2011-2367", "CVE-2011-2368", "CVE-2011-2369", "CVE-2011-2370", "CVE-2011-2371", "CVE-2011-2373", "CVE-2011-2374", "CVE-2011-2375", "CVE-2011-2377");
  script_xref(name:"USN", value:"1157-3");

  script_name(english:"Ubuntu 11.04 : firefox regression (USN-1157-3)");
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
"USN-1157-1 fixed vulnerabilities in Firefox. Unfortunately, this
update produced the side effect of pulling in Firefox on some systems
that did not have it installed during a dist-upgrade due to changes in
the Ubuntu language packs. This update fixes the problem. We apologize
for the inconvenience.

Bob Clary, Kevin Brosnan, Gary Kwong, Jesse Ruderman, Christian
Biesinger, Bas Schouten, Igor Bukanov, Bill McCloskey, Olli Pettay,
Daniel Veditz and Marcia Knous discovered multiple memory
vulnerabilities in the browser rendering engine. An attacker could
possibly execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2011-2374, CVE-2011-2375)

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

It was discovered that Firefox's WebGL textures did not
honor same-origin policy. If a user were tricked into
viewing a malicious site, an attacker could potentially view
image data from a different site. (CVE-2011-2366)

Christoph Diehl discovered an out-of-bounds read
vulnerability in WebGL code. An attacker could potentially
read data that other processes had stored in the GPU.
(CVE-2011-2367)

Christoph Diehl discovered an invalid write vulnerability in
WebGL code. An attacker could potentially use this to
execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2011-2368)

It was discovered that an unauthorized site could trigger an
installation dialog for addons and themes. If a user were
tricked into viewing a malicious site, an attacker could
possibly trick the user into installing a malicious addon or
theme. (CVE-2011-2370)

Mario Heiderich discovered a vulnerability in displaying
decoded HTML-encoded entities inside SVG elements. An
attacker could utilize this to perform cross-site scripting
attacks. (CVE-2011-2369).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox Array.reduceRight() Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-lg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-zh-hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-zh-hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-zu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/24");
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

if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-af", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-ar", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-as", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-ast", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-be", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-bg", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-bn", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-br", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-bs", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-ca", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-cs", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-cy", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-da", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-de", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-el", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-en", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-eo", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-es", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-et", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-eu", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-fa", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-fi", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-fr", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-fy", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-ga", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-gd", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-gl", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-gu", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-he", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-hi", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-hr", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-hu", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-hy", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-id", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-is", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-it", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-ja", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-ka", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-kk", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-kn", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-ko", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-ku", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-lg", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-lt", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-lv", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-mai", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-mk", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-ml", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-mr", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-nb", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-nl", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-nn", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-nso", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-oc", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-or", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-pa", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-pl", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-pt", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-ro", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-ru", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-si", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-sk", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-sl", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-sq", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-sr", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-sv", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-ta", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-te", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-th", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-tr", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-uk", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-vi", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-zh-hans", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-zh-hant", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"firefox-locale-zu", pkgver:"5.0+build1+nobinonly-0ubuntu0.11.04.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox-locale-af / firefox-locale-ar / firefox-locale-as / etc");
}
