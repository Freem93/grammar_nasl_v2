#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1924-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69234);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/25 16:27:06 $");

  script_cve_id("CVE-2013-1701", "CVE-2013-1702", "CVE-2013-1704", "CVE-2013-1705", "CVE-2013-1708", "CVE-2013-1709", "CVE-2013-1710", "CVE-2013-1711", "CVE-2013-1713", "CVE-2013-1714", "CVE-2013-1717");
  script_bugtraq_id(61641);
  script_osvdb_id(96010, 96011, 96012, 96013, 96014, 96017, 96018, 96019, 96020, 96022, 96023);
  script_xref(name:"USN", value:"1924-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.04 : firefox vulnerabilities (USN-1924-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jeff Gilbert, Henrik Skupin, Ben Turner, Christian Holler, Andrew
McCreight, Gary Kwong, Jan Varga and Jesse Ruderman discovered
multiple memory safety issues in Firefox. If the user were tricked in
to opening a specially crafted page, an attacker could possibly
exploit these to cause a denial of service via application crash, or
potentially execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2013-1701, CVE-2013-1702)

A use-after-free bug was discovered when the DOM is modified during a
SetBody mutation event. If the user were tricked in to opening a
specially crafted page, an attacker could potentially exploit this to
execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2013-1704)

A use-after-free bug was discovered when generating a CRMF request
with certain parameters. If the user were tricked in to opening a
specially crafted page, an attacker could potentially exploit this to
execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2013-1705)

Aki Helin discovered a crash when decoding a WAV file in some
circumstances. An attacker could potentially exploit this to cause a
denial of service. (CVE-2013-1708)

It was discovered that a document's URI could be set to the URI of a
different document. An attacker could potentially exploit this to
conduct cross-site scripting (XSS) attacks. (CVE-2013-1709)

A flaw was discovered when generating a CRMF request in certain
circumstances. An attacker could potentially exploit this to conduct
cross-site scripting (XSS) attacks, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2013-1710)

Bobby Holley discovered that XBL scopes could be used to circumvent
XrayWrappers in certain circumstances. An attacked could potentially
exploit this to conduct cross-site scripting (XSS) attacks or cause
undefined behaviour. (CVE-2013-1711)

Cody Crews discovered that some JavaScript components performed
security checks against the wrong URI, potentially bypassing
same-origin policy restrictions. An attacker could exploit this to
conduct cross-site scripting (XSS) attacks or install addons from a
malicious site. (CVE-2013-1713)

Federico Lanusse discovered that web workers could bypass cross-origin
checks when using XMLHttpRequest. An attacker could potentially
exploit this to conduct cross-site scripting (XSS) attacks.
(CVE-2013-1714)

Georgi Guninski and John Schoenick discovered that Java applets could
access local files under certain circumstances. An attacker could
potentially exploit this to steal confidential data. (CVE-2013-1717).

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
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox toString console.time Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/07");
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
if (! ereg(pattern:"^(12\.04|12\.10|13\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10 / 13.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"23.0+build2-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"firefox", pkgver:"23.0+build2-0ubuntu0.12.10.1")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"firefox", pkgver:"23.0+build2-0ubuntu0.13.04.1")) flag++;

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
