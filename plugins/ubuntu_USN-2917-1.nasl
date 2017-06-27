#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2917-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(89826);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/05/26 16:22:51 $");

  script_cve_id("CVE-2016-1950", "CVE-2016-1952", "CVE-2016-1953", "CVE-2016-1954", "CVE-2016-1955", "CVE-2016-1956", "CVE-2016-1957", "CVE-2016-1958", "CVE-2016-1959", "CVE-2016-1960", "CVE-2016-1961", "CVE-2016-1962", "CVE-2016-1963", "CVE-2016-1964", "CVE-2016-1965", "CVE-2016-1966", "CVE-2016-1967", "CVE-2016-1968", "CVE-2016-1973", "CVE-2016-1974", "CVE-2016-1977", "CVE-2016-2790", "CVE-2016-2791", "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795", "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799", "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802");
  script_xref(name:"USN", value:"2917-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 / 15.10 : firefox vulnerabilities (USN-2917-1)");
  script_summary(english:"Checks dpkg output for updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Francis Gabriel discovered a buffer overflow during ASN.1 decoding in
NSS. If a user were tricked in to opening a specially crafted website,
an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2016-1950)

Bob Clary, Christoph Diehl, Christian Holler, Andrew McCreight, Daniel
Holbert, Jesse Ruderman, Randell Jesup, Carsten Book, Gian-Carlo
Pascutto, Tyson Smith, Andrea Marchesini, and Jukka Jylanki
discovered multiple memory safety issues in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2016-1952, CVE-2016-1953)

Nicolas Golubovic discovered that CSP violation reports can be used to
overwrite local files. If a user were tricked in to opening a
specially crafted website with addon signing disabled and unpacked
addons installed, an attacker could potentially exploit this to gain
additional privileges. (CVE-2016-1954)

Muneaki Nishimura discovered that CSP violation reports contained full
paths for cross-origin iframe navigations. An attacker could
potentially exploit this to steal confidential data. (CVE-2016-1955)

Ucha Gobejishvili discovered that performing certain WebGL operations
resulted in memory resource exhaustion with some Intel GPUs, requiring
a reboot. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service. (CVE-2016-1956)

Jose Martinez and Romina Santillan discovered a memory leak in
libstagefright during MPEG4 video file processing in some
circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via memory exhaustion. (CVE-2016-1957)

Abdulrahman Alqabandi discovered that the addressbar could be blank or
filled with page defined content in some circumstances. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to conduct URL spoofing attacks.
(CVE-2016-1958)

Looben Yang discovered an out-of-bounds read in Service Worker
Manager. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2016-1959)

A use-after-free was discovered in the HTML5 string parser. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2016-1960)

A use-after-free was discovered in the SetBody function of
HTMLDocument. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2016-1961)

Dominique Hazael-Massieux discovered a use-after-free when using
multiple WebRTC data channels. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2016-1962)

It was discovered that Firefox crashes when local files are modified
whilst being read by the FileReader API. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2016-1963)

Nicolas Gregoire discovered a use-after-free during XML
transformations. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox. (CVE-2016-1964)

Tsubasa Iinuma discovered a mechanism to cause the addressbar to
display an incorrect URL, using history navigations and the Location
protocol property. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to conduct
URL spoofing attacks. (CVE-2016-1965)

A memory corruption issues was discovered in the NPAPI subsystem. If a
user were tricked in to opening a specially crafted website with a
malicious plugin installed, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2016-1966)

Jordi Chancel discovered a same-origin-policy bypass when using
performance.getEntries and history navigation with session restore. If
a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to steal confidential data.
(CVE-2016-1967)

Luke Li discovered a buffer overflow during Brotli decompression in
some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox. (CVE-2016-1968)

Ronald Crane discovered a use-after-free in GetStaticInstance in
WebRTC. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2016-1973)

Ronald Crane discovered an out-of-bounds read following a failed
allocation in the HTML parser in some circumstances. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2016-1974)

Holger Fuhrmannek, Tyson Smith and Holger Fuhrmannek reported multiple
memory safety issues in the Graphite 2 library. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2016-1977, CVE-2016-2790, CVE-2016-2791,
CVE-2016-2792, CVE-2016-2793, CVE-2016-2794, CVE-2016-2795,
CVE-2016-2796, CVE-2016-2797, CVE-2016-2798, CVE-2016-2799,
CVE-2016-2800, CVE-2016-2801, CVE-2016-2802)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}



include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

# Temp disable
exit(0, "This plugin is temporarily disabled.");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/Ubuntu/release") ) audit(AUDIT_OS_NOT, "Ubuntu");
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"45.0+build2-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"45.0+build2-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"firefox", pkgver:"45.0+build2-0ubuntu0.15.10.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
