#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1430-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58923);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/25 16:11:46 $");

  script_cve_id("CVE-2011-1187", "CVE-2011-3062", "CVE-2012-0467", "CVE-2012-0468", "CVE-2012-0469", "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0473", "CVE-2012-0474", "CVE-2012-0475", "CVE-2012-0477", "CVE-2012-0478", "CVE-2012-0479");
  script_osvdb_id(72475, 80740, 81513, 81514, 81515, 81516, 81517, 81519, 81520, 81521, 81522, 81523, 81524, 81526);
  script_xref(name:"USN", value:"1430-2");

  script_name(english:"Ubuntu 10.04 LTS / 11.04 / 11.10 : ubufox update (USN-1430-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-1430-1 fixed vulnerabilities in Firefox. This update provides an
updated ubufox package for use with the latest Firefox.

Bob Clary, Christian Holler, Brian Hackett, Bobby Holley, Gary Kwong,
Hilary Hall, Honza Bambas, Jesse Ruderman, Julian Seward, and Olli
Pettay discovered memory safety issues affecting Firefox. If the user
were tricked into opening a specially crafted page, an attacker could
exploit these to cause a denial of service via application crash, or
potentially execute code with the privileges of the user invoking
Firefox. (CVE-2012-0467, CVE-2012-0468)

Aki Helin discovered a use-after-free vulnerability in
XPConnect. An attacker could potentially exploit this to
execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2012-0469)

Atte Kettunen discovered that invalid frees cause heap
corruption in gfxImageSurface. If a user were tricked into
opening a malicious Scalable Vector Graphics (SVG) image
file, an attacker could exploit these to cause a denial of
service via application crash, or potentially execute code
with the privileges of the user invoking Firefox.
(CVE-2012-0470)

Anne van Kesteren discovered a potential cross-site
scripting (XSS) vulnerability via multibyte content
processing errors. With cross-site scripting
vulnerabilities, if a user were tricked into viewing a
specially crafted page, a remote attacker could exploit this
to modify the contents, or steal confidential data, within
the same domain. (CVE-2012-0471)

Matias Juntunen discovered a vulnerability in Firefox's
WebGL implementation that potentially allows the reading of
illegal video memory. An attacker could possibly exploit
this to cause a denial of service via application crash.
(CVE-2012-0473)

Jordi Chancel, Eddy Bordi, and Chris McGowen discovered that
Firefox allowed the address bar to display a different
website than the one the user was visiting. This could
potentially leave the user vulnerable to cross-site
scripting (XSS) attacks. With cross-site scripting
vulnerabilities, if a user were tricked into viewing a
specially crafted page, a remote attacker could exploit this
to modify the contents, or steal confidential data, within
the same domain. (CVE-2012-0474)

Simone Fabiano discovered that Firefox did not always send
correct origin headers when connecting to an IPv6 websites.
An attacker could potentially use this to bypass intended
access controls. (CVE-2012-0475)

Masato Kinugawa discovered that cross-site scripting (XSS)
injection is possible during the decoding of ISO-2022-KR and
ISO-2022-CN character sets. With cross-site scripting
vulnerabilities, if a user were tricked into viewing a
specially crafted page, a remote attacker could exploit this
to modify the contents, or steal confidential data, within
the same domain. (CVE-2012-0477)

It was discovered that certain images rendered using WebGL
could cause Firefox to crash. If the user were tricked into
opening a specially crafted page, an attacker could exploit
this to cause a denial of service via application crash, or
potentially execute code with the privileges of the user
invoking Firefox. (CVE-2012-0478)

Mateusz Jurczyk discovered an off-by-one error in the
OpenType Sanitizer. If the user were tricked into opening a
specially crafted page, an attacker could exploit this to
cause a denial of service via application crash, or
potentially execute code with the privileges of the user
invoking Firefox. (CVE-2011-3062)

Daniel Divricean discovered a defect in the error handling
of JavaScript errors can potentially leak the file names and
location of JavaScript files on a server. This could
potentially lead to inadvertent information disclosure and a
vector for further attacks. (CVE-2011-1187)

Jeroen van der Gun discovered a vulnerability in the way
Firefox handled RSS and Atom feeds. Invalid RSS or ATOM
content loaded over HTTPS caused the location bar to be
updated with the address of this content, while the main
window still displays the previously loaded content. An
attacker could potentially exploit this vulnerability to
conduct phishing attacks. (CVE-2012-0479).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xul-ext-ubufox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-ubufox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/30");
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
if (! ereg(pattern:"^(10\.04|11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"xul-ext-ubufox", pkgver:"0.9.5-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"xul-ext-ubufox", pkgver:"0.9.5-0ubuntu1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"xul-ext-ubufox", pkgver:"1.0.4-0ubuntu1")) flag++;

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
