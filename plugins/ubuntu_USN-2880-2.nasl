#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2880-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88637);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2016-1930", "CVE-2016-1931", "CVE-2016-1933", "CVE-2016-1935", "CVE-2016-1937", "CVE-2016-1938", "CVE-2016-1939", "CVE-2016-1942", "CVE-2016-1944", "CVE-2016-1945", "CVE-2016-1946", "CVE-2016-1947");
  script_osvdb_id(133629, 133630, 133631, 133632, 133633, 133634, 133635, 133636, 133637, 133638, 133639, 133640, 133641, 133642, 133643, 133644, 133645, 133646, 133647, 133648, 133649, 133650, 133651, 133652, 133653, 133654, 133656, 133657, 133659, 133660, 133661, 133662, 133669, 133682, 133684);
  script_xref(name:"USN", value:"2880-2");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 : firefox regression (USN-2880-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-2880-1 fixed vulnerabilities in Firefox. This update introduced a
regression which caused Firefox to crash on startup with some
configurations. This update fixes the problem.

We apologize for the inconvenience.

Bob Clary, Christian Holler, Nils Ohlmeier, Gary Kwong, Jesse
Ruderman, Carsten Book, Randell Jesup, Nicolas Pierron, Eric Rescorla,
Tyson Smith, and Gabor Krizsanits discovered multiple memory safety
issues in Firefox. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these to cause
a denial of service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox. (CVE-2016-1930,
CVE-2016-1931)

Gustavo Grieco discovered an out-of-memory crash when
loading GIF images in some circumstances. If a user were
tricked in to opening a specially crafted website, an
attacker could exploit this to cause a denial of service.
(CVE-2016-1933)

Aki Helin discovered a buffer overflow when rendering WebGL
content in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2016-1935)

It was discovered that a delay was missing when focusing the
protocol handler dialog. If a user were tricked in to
opening a specially crafted website, an attacker could
potentially exploit this to conduct clickjacking attacks.
(CVE-2016-1937)

Hanno Bock discovered that calculations with mp_div and
mp_exptmod in NSS produce incorrect results in some
circumstances, resulting in cryptographic weaknesses.
(CVE-2016-1938)

Nicholas Hurley discovered that Firefox allows for control
characters to be set in cookie names. An attacker could
potentially exploit this to conduct cookie injection attacks
on some web servers. (CVE-2016-1939)

It was discovered that when certain invalid URLs are pasted
in to the addressbar, the addressbar contents may be
manipulated to show the location of arbitrary websites. An
attacker could potentially exploit this to conduct URL
spoofing attacks. (CVE-2016-1942)

Ronald Crane discovered three vulnerabilities through code
inspection. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these
to cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2016-1944, CVE-2016-1945,
CVE-2016-1946)

Francois Marier discovered that Application Reputation
lookups didn't work correctly, disabling warnings for
potentially malicious downloads. An attacker could
potentially exploit this by tricking a user in to
downloading a malicious file. Other parts of the Safe
Browsing feature were unaffected by this. (CVE-2016-1947).

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
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/09");
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

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"44.0.1+build2-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"44.0.1+build2-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"firefox", pkgver:"44.0.1+build2-0ubuntu0.15.10.1")) flag++;

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
