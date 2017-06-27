#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2785-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86758);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2015-4513", "CVE-2015-4514", "CVE-2015-4515", "CVE-2015-4518", "CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183", "CVE-2015-7187", "CVE-2015-7188", "CVE-2015-7189", "CVE-2015-7193", "CVE-2015-7194", "CVE-2015-7195", "CVE-2015-7196", "CVE-2015-7197", "CVE-2015-7198", "CVE-2015-7199", "CVE-2015-7200");
  script_osvdb_id(129763, 129764, 129765, 129766, 129767, 129768, 129769, 129770, 129771, 129772, 129773, 129774, 129775, 129776, 129777, 129778, 129779, 129780, 129781, 129782, 129783, 129784, 129785, 129786, 129787, 129788, 129789, 129790, 129791, 129797, 129798, 129799, 129800, 129801);
  script_xref(name:"USN", value:"2785-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.04 / 15.10 : firefox vulnerabilities (USN-2785-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Christian Holler, David Major, Jesse Ruderman, Tyson Smith, Boris
Zbarsky, Randell Jesup, Olli Pettay, Karl Tomlinson, Jeff Walden, Gary
Kwong, Andrew McCreight, Georg Fritzsche, and Carsten Book discovered
multiple memory safety issues in Firefox. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit these to cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-4513, CVE-2015-4514)

Tim Brown discovered that Firefox discloses the hostname during NTLM
authentication in some circumstances. If a user were tricked in to
opening a specially crafted website with NTLM v1 enabled, an attacker
could exploit this to obtain sensitive information. (CVE-2015-4515)

Mario Heiderich and Frederik Braun discovered that CSP could be
bypassed in reader mode in some circumstances. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit this to conduct cross-site scripting (XSS)
attacks. (CVE-2015-4518)

Tyson Smith and David Keeler discovered a use-after-poison and buffer
overflow in NSS. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these to cause
a denial of service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox. (CVE-2015-7181,
CVE-2015-7182)

Ryan Sleevi discovered an integer overflow in NSPR. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2015-7183)

Jason Hamilton, Peter Arremann and Sylvain Giroux discovered that
panels created via the Addon SDK with { script: false } could still
execute inline script. If a user installed an addon that relied on
this as a security mechanism, an attacker could potentially exploit
this to conduct cross-site scripting (XSS) attacks, depending on the
source of the panel content. (CVE-2015-7187)

Michal Bentkowski discovered that adding white-space to hostnames
that are IP address can bypass same-origin protections. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to conduct cross-site scripting (XSS)
attacks. (CVE-2015-7188)

Looben Yang discovered a buffer overflow during script interactions
with the canvas element in some circumstances. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2015-7189)

Shinto K Anto discovered that CORS preflight is bypassed when
receiving non-standard Content-Type headers in some circumstances. If
a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to bypass same-origin
restrictions. (CVE-2015-7193)

Gustavo Grieco discovered a buffer overflow in libjar in some
circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox. (CVE-2015-7194)

Frans Rosen discovered that certain escaped characters in the
Location header are parsed incorrectly, resulting in a navigation to
the previously parsed version of a URL. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to obtain site specific tokens. (CVE-2015-7195)

Vytautas Staraitis discovered a garbage collection crash when
interacting with Java applets in some circumstances. If a user were
tricked in to opening a specially crafted website with the Java plugin
installed, an attacker could potentially exploit this to execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2015-7196)

Ehsan Akhgari discovered a mechanism for a web worker to bypass secure
requirements for web sockets. If a user were tricked in to opening a
specially crafted website, an attacker could exploit this to bypass
the mixed content web socket policy. (CVE-2015-7197)

Ronald Crane discovered several vulnerabilities through
code-inspection. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these to cause
a denial of service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox. (CVE-2015-7198,
CVE-2015-7199, CVE-2015-7200).

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
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/05");
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

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"42.0+build2-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"42.0+build2-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"firefox", pkgver:"42.0+build2-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"firefox", pkgver:"42.0+build2-0ubuntu0.15.10.1")) flag++;

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
