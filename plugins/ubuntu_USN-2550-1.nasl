#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2550-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82524);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2015-0801", "CVE-2015-0802", "CVE-2015-0803", "CVE-2015-0804", "CVE-2015-0805", "CVE-2015-0806", "CVE-2015-0807", "CVE-2015-0808", "CVE-2015-0811", "CVE-2015-0812", "CVE-2015-0813", "CVE-2015-0814", "CVE-2015-0815", "CVE-2015-0816");
  script_bugtraq_id(73454, 73455, 73457, 73458, 73460, 73461, 73462, 73463, 73464, 73465, 73466, 73467);
  script_osvdb_id(119753, 120077, 120078, 120079, 120090, 120092, 120101, 120102, 120106, 120107);
  script_xref(name:"USN", value:"2550-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 14.10 : firefox vulnerabilities (USN-2550-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Olli Pettay and Boris Zbarsky discovered an issue during anchor
navigations in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to bypass same-origin policy restrictions.
(CVE-2015-0801)

Bobby Holley discovered that windows created to hold privileged UI
content retained access to privileged internal methods if navigated to
unprivileged content. An attacker could potentially exploit this in
combination with another flaw, in order to execute arbitrary script in
a privileged context. (CVE-2015-0802)

Several type confusion issues were discovered in Firefox. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit these to cause a denial of service via
application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2015-0803, CVE-2015-0804)

Abhishek Arya discovered memory corruption issues during 2D graphics
rendering. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial
of service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-0805,
CVE-2015-0806)

Christoph Kerschbaumer discovered that CORS requests from
navigator.sendBeacon() followed 30x redirections after preflight. If a
user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to conduct cross-site request
forgery (XSRF) attacks. (CVE-2015-0807)

Mitchell Harper discovered an issue with memory management of
simple-type arrays in WebRTC. An attacker could potentially exploit
this to cause undefined behaviour. (CVE-2015-0808)

Felix Grobert discovered an out-of-bounds read in the QCMS colour
management library. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to obtain
sensitive information. (CVE-2015-0811)

Armin Razmdjou discovered that lightweight themes could be installed
in Firefox without a user approval message, from Mozilla subdomains
over HTTP without SSL. A remote attacker could potentially exploit
this by conducting a Man-In-The-Middle (MITM) attack to install themes
without user approval. (CVE-2015-0812)

Aki Helin discovered a use-after-free when playing MP3 audio files
using the Fluendo MP3 GStreamer plugin in certain circumstances. If a
user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via application crash, or execute arbitrary code with the privileges
of the user invoking Firefox. (CVE-2015-0813)

Christian Holler, Andrew McCreight, Gary Kwong, Karl Tomlinson,
Randell Jesup, Shu-yu Guo, Steve Fink, Tooru Fujisawa, and Byron
Campen discovered multiple memory safety issues in Firefox. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit these to cause a denial of service via
application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2015-0814, CVE-2015-0815)

Mariusz Mlynski discovered that documents loaded via resource: URLs
(such as PDF.js) could load privileged chrome pages. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this in combination with another flaw, in order to
execute arbitrary script in a privileged context. (CVE-2015-0816).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox PDF.js Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/02");
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

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"37.0+build2-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"37.0+build2-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"firefox", pkgver:"37.0+build2-0ubuntu0.14.10.1")) flag++;

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
