#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2458-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80549);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/08/22 14:13:37 $");

  script_cve_id("CVE-2014-8634", "CVE-2014-8635", "CVE-2014-8636", "CVE-2014-8637", "CVE-2014-8638", "CVE-2014-8639", "CVE-2014-8640", "CVE-2014-8641", "CVE-2014-8642");
  script_bugtraq_id(72041, 72042, 72044, 72045, 72046, 72047, 72048, 72049, 72050);
  script_xref(name:"USN", value:"2458-2");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 14.10 : ubufox update (USN-2458-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-2458-1 fixed vulnerabilities in Firefox. This update provides the
corresponding version of Ubufox.

Christian Holler, Patrick McManus, Christoph Diehl, Gary Kwong, Jesse
Ruderman, Byron Campen, Terrence Cole, and Nils Ohlmeier discovered
multiple memory safety issues in Firefox. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit these to cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2014-8634, CVE-2014-8635)

Bobby Holley discovered that some DOM objects with certain
properties can bypass XrayWrappers in some circumstances. If
a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to
bypass security restrictions. (CVE-2014-8636)

Michal Zalewski discovered a use of uninitialized memory
when rendering malformed bitmap images on a canvas element.
If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to steal
confidential information. (CVE-2014-8637)

Muneaki Nishimura discovered that requests from
navigator.sendBeacon() lack an origin header. If a user were
tricked in to opening a specially crafted website, an
attacker could potentially exploit this to conduct
cross-site request forgery (XSRF) attacks. (CVE-2014-8638)

Xiaofeng Zheng discovered that a web proxy returning a 407
response could inject cookies in to the originally requested
domain. If a user connected to a malicious web proxy, an
attacker could potentially exploit this to conduct
session-fixation attacks. (CVE-2014-8639)

Holger Fuhrmannek discovered a crash in Web Audio while
manipulating timelines. If a user were tricked in to opening
a specially crafted website, an attacker could potentially
exploit this to cause a denial of service. (CVE-2014-8640)

Mitchell Harper discovered a use-after-free in WebRTC. If a
user were tricked in to opening a specially crafted website,
an attacker could potentially exploit this to cause a denial
of service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox.
(CVE-2014-8641)

Brian Smith discovered that OCSP responses would fail to
verify if signed by a delegated OCSP responder certificate
with the id-pkix-ocsp-nocheck extension, potentially
allowing a user to connect to a site with a revoked
certificate. (CVE-2014-8642).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xul-ext-ubufox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox Proxy Prototype Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-ubufox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/15");
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
if (! ereg(pattern:"^(12\.04|14\.04|14\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 14.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"xul-ext-ubufox", pkgver:"3.0-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"xul-ext-ubufox", pkgver:"3.0-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"xul-ext-ubufox", pkgver:"3.0-0ubuntu0.14.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xul-ext-ubufox");
}
