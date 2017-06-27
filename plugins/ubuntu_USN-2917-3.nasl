#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2917-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90598);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/01 20:56:53 $");

  script_cve_id("CVE-2016-1950", "CVE-2016-1952", "CVE-2016-1953", "CVE-2016-1954", "CVE-2016-1955", "CVE-2016-1956", "CVE-2016-1957", "CVE-2016-1958", "CVE-2016-1959", "CVE-2016-1960", "CVE-2016-1961", "CVE-2016-1962", "CVE-2016-1963", "CVE-2016-1964", "CVE-2016-1965", "CVE-2016-1966", "CVE-2016-1967", "CVE-2016-1968", "CVE-2016-1973", "CVE-2016-1974", "CVE-2016-1977", "CVE-2016-2790", "CVE-2016-2791", "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795", "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799", "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802");
  script_osvdb_id(135550, 135551, 135552, 135553, 135554, 135555, 135556, 135557, 135558, 135559, 135560, 135561, 135562, 135563, 135564, 135565, 135566, 135567, 135568, 135569, 135570, 135571, 135572, 135573, 135574, 135575, 135576, 135577, 135578, 135579, 135580, 135581, 135582, 135583, 135584, 135585, 135591, 135592, 135593, 135594, 135595, 135601, 135602, 135603, 135605, 135606, 135607, 135608, 135609, 135610, 135611, 135612, 135613, 135614, 135615, 135616, 135617, 135618);
  script_xref(name:"USN", value:"2917-3");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 : firefox regressions (USN-2917-3)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-2917-1 fixed vulnerabilities in Firefox. This update caused
several web compatibility regressions.

This update fixes the problem.

We apologize for the inconvenience.

Francis Gabriel discovered a buffer overflow during ASN.1 decoding in
NSS. If a user were tricked in to opening a specially crafted website,
an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2016-1950)

Bob Clary, Christoph Diehl, Christian Holler, Andrew
McCreight, Daniel Holbert, Jesse Ruderman, Randell Jesup,
Carsten Book, Gian-Carlo Pascutto, Tyson Smith, Andrea
Marchesini, and Jukka Jylanki discovered multiple memory
safety issues in Firefox. If a user were tricked in to
opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via
application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2016-1952,
CVE-2016-1953)

Nicolas Golubovic discovered that CSP violation reports can
be used to overwrite local files. If a user were tricked in
to opening a specially crafted website with addon signing
disabled and unpacked addons installed, an attacker could
potentially exploit this to gain additional privileges.
(CVE-2016-1954)

Muneaki Nishimura discovered that CSP violation reports
contained full paths for cross-origin iframe navigations. An
attacker could potentially exploit this to steal
confidential data. (CVE-2016-1955)

Ucha Gobejishvili discovered that performing certain WebGL
operations resulted in memory resource exhaustion with some
Intel GPUs, requiring a reboot. If a user were tricked in to
opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service.
(CVE-2016-1956)

Jose Martinez and Romina Santillan discovered a memory leak
in libstagefright during MPEG4 video file processing in some
circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially
exploit this to cause a denial of service via memory
exhaustion. (CVE-2016-1957)

Abdulrahman Alqabandi discovered that the addressbar could
be blank or filled with page defined content in some
circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially
exploit this to conduct URL spoofing attacks.
(CVE-2016-1958)

Looben Yang discovered an out-of-bounds read in Service
Worker Manager. If a user were tricked in to opening a
specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2016-1959)

A use-after-free was discovered in the HTML5 string parser.
If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause
a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking
Firefox. (CVE-2016-1960)

A use-after-free was discovered in the SetBody function of
HTMLDocument. If a user were tricked in to opening a
specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2016-1961)

Dominique Hazael-Massieux discovered a use-after-free when
using multiple WebRTC data channels. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2016-1962)

It was discovered that Firefox crashes when local files are
modified whilst being read by the FileReader API. If a user
were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to execute arbitrary
code with the privileges of the user invoking Firefox.
(CVE-2016-1963)

Nicolas Gregoire discovered a use-after-free during XML
transformations. If a user were tricked in to opening a
specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2016-1964)

Tsubasa Iinuma discovered a mechanism to cause the
addressbar to display an incorrect URL, using history
navigations and the Location protocol property. If a user
were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to conduct URL
spoofing attacks. (CVE-2016-1965)

A memory corruption issues was discovered in the NPAPI
subsystem. If a user were tricked in to opening a specially
crafted website with a malicious plugin installed, an
attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox.
(CVE-2016-1966)

Jordi Chancel discovered a same-origin-policy bypass when
using performance.getEntries and history navigation with
session restore. If a user were tricked in to opening a
specially crafted website, an attacker could potentially
exploit this to steal confidential data. (CVE-2016-1967)

Luke Li discovered a buffer overflow during Brotli
decompression in some circumstances. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2016-1968)

Ronald Crane discovered a use-after-free in
GetStaticInstance in WebRTC. If a user were tricked in to
opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2016-1973)

Ronald Crane discovered an out-of-bounds read following a
failed allocation in the HTML parser in some circumstances.
If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause
a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking
Firefox. (CVE-2016-1974)

Holger Fuhrmannek, Tyson Smith and Holger Fuhrmannek
reported multiple memory safety issues in the Graphite 2
library. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these
to cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2016-1977, CVE-2016-2790,
CVE-2016-2791, CVE-2016-2792, CVE-2016-2793, CVE-2016-2794,
CVE-2016-2795, CVE-2016-2796, CVE-2016-2797, CVE-2016-2798,
CVE-2016-2799, CVE-2016-2800, CVE-2016-2801, CVE-2016-2802).

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
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/20");
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

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(12\.04|14\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"45.0.2+build1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"45.0.2+build1-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"firefox", pkgver:"45.0.2+build1-0ubuntu0.15.10.1")) flag++;

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
