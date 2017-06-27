#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1112-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55070);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/26 16:14:08 $");

  script_cve_id("CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0067", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0071", "CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080", "CVE-2011-0081", "CVE-2011-1202");
  script_osvdb_id(72075, 72076, 72077, 72078, 72080, 72081, 72082, 72083, 72084, 72085, 72086, 72087, 72088, 72090, 72094);
  script_xref(name:"USN", value:"1112-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : firefox, firefox-3.0, firefox-3.5, xulrunner-1.9.2 vulnerabilities (USN-1112-1)");
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
"It was discovered that there was a vulnerability in the memory
handling of certain types of content. An attacker could exploit this
to possibly run arbitrary code as the user running Firefox.
(CVE-2011-0081)

It was discovered that Firefox incorrectly handled certain JavaScript
requests. An attacker could exploit this to possibly run arbitrary
code as the user running Firefox. (CVE-2011-0069)

Ian Beer discovered a vulnerability in the memory handling of a
certain types of documents. An attacker could exploit this to possibly
run arbitrary code as the user running Firefox. (CVE-2011-0070)

Bob Clary, Henri Sivonen, Marco Bonardo, Mats Palmgren and Jesse
Ruderman discovered several memory vulnerabilities. An attacker could
exploit these to possibly run arbitrary code as the user running
Firefox. (CVE-2011-0080)

Aki Helin discovered multiple vulnerabilities in the HTML rendering
code. An attacker could exploit these to possibly run arbitrary code
as the user running Firefox. (CVE-2011-0074, CVE-2011-0075)

Ian Beer discovered multiple overflow vulnerabilities. An attacker
could exploit these to possibly run arbitrary code as the user running
Firefox. (CVE-2011-0077, CVE-2011-0078)

Martin Barbella discovered a memory vulnerability in the handling of
certain DOM elements. An attacker could exploit this to possibly run
arbitrary code as the user running Firefox. (CVE-2011-0072)

It was discovered that there were use-after-free vulnerabilities in
Firefox's mChannel and mObserverList objects. An attacker could
exploit these to possibly run arbitrary code as the user running
Firefox. (CVE-2011-0065, CVE-2011-0066)

It was discovered that there was a vulnerability in the handling of
the nsTreeSelection element. An attacker serving malicious content
could exploit this to possibly run arbitrary code as the user running
Firefox. (CVE-2011-0073)

Paul Stone discovered a vulnerability in the handling of Java applets.
An attacker could use this to mimic interaction with form autocomplete
controls and steal entries from the form history. (CVE-2011-0067)

Soroush Dalili discovered a vulnerability in the resource: protocol.
This could potentially allow an attacker to load arbitrary files that
were accessible to the user running Firefox. (CVE-2011-0071)

Chris Evans discovered a vulnerability in Firefox's XSLT generate-id()
function. An attacker could possibly use this vulnerability to make
other attacks more reliable. (CVE-2011-1202).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox and / or xulrunner-1.9.2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox "nsTreeRange" Dangling Pointer Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xulrunner-1.9.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/13");
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
if (! ereg(pattern:"^(8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"firefox", pkgver:"3.6.17+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.17+build3+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"firefox", pkgver:"3.6.17+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.17+build3+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"firefox", pkgver:"3.6.17+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.17+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"firefox", pkgver:"3.6.17+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xulrunner-1.9.2", pkgver:"1.9.2.17+build3+nobinonly-0ubuntu0.10.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / xulrunner-1.9.2");
}
