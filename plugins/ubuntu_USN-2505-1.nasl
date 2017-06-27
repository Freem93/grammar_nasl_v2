#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2505-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81544);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/24 17:37:08 $");

  script_cve_id("CVE-2015-0819", "CVE-2015-0820", "CVE-2015-0821", "CVE-2015-0822", "CVE-2015-0823", "CVE-2015-0824", "CVE-2015-0825", "CVE-2015-0826", "CVE-2015-0827", "CVE-2015-0829", "CVE-2015-0830", "CVE-2015-0831", "CVE-2015-0832", "CVE-2015-0834", "CVE-2015-0835", "CVE-2015-0836");
  script_bugtraq_id(72741, 72742, 72743, 72745, 72746, 72748, 72750, 72751, 72752, 72753, 72754, 72755, 72756, 72757, 72758, 72759);
  script_osvdb_id(118696, 118697, 118699, 118704, 118705, 118707, 118710, 118711, 118712, 118717, 118718, 118719, 118720, 118721, 118722);
  script_xref(name:"USN", value:"2505-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 14.10 : firefox vulnerabilities (USN-2505-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Matthew Noorenberghe discovered that whitelisted Mozilla domains could
make UITour API calls from background tabs. If one of these domains
were compromised and open in a background tab, an attacker could
potentially exploit this to conduct clickjacking attacks.
(CVE-2015-0819)

Jan de Mooij discovered an issue that affects content using the Caja
Compiler. If web content loads specially crafted code, this could be
used to bypass sandboxing security measures provided by Caja.
(CVE-2015-0820)

Armin Razmdjou discovered that opening hyperlinks with specific mouse
and key combinations could allow a Chrome privileged URL to be opened
without context restrictions being preserved. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit this to bypass security restrictions.
(CVE-2015-0821)

Armin Razmdjou discovered that contents of locally readable files
could be made available via manipulation of form autocomplete in some
circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to obtain
sensitive information. (CVE-2015-0822)

Atte Kettunen discovered a use-after-free in the OpenType Sanitiser
(OTS) in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to cause a denial of service via application crash. (CVE-2015-0823)

Atte Kettunen discovered a crash when drawing images using Cairo in
some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service. (CVE-2015-0824)

Atte Kettunen discovered a buffer underflow during playback of MP3
files in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to obtain sensitive information. (CVE-2015-0825)

Atte Kettunen discovered a buffer overflow during CSS restyling in
some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox. (CVE-2015-0826)

Abhishek Arya discovered an out-of-bounds read and write when
rendering SVG content in some circumstances. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to obtain sensitive information. (CVE-2015-0827)

A buffer overflow was discovered in libstagefright during video
playback in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2015-0829)

Daniele Di Proietto discovered that WebGL could cause a crash in some
circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service. (CVE-2015-0830)

Paul Bandha discovered a use-after-free in IndexedDB. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2015-0831)

Muneaki Nishimura discovered that a period appended to a hostname
could bypass key pinning and HSTS in some circumstances. A remote
attacker could potentially exloit this to conduct a Man-in-the-middle
(MITM) attack. (CVE-2015-0832)

Alexander Kolesnik discovered that Firefox would attempt plaintext
connections to servers when handling turns: and stuns: URIs. A remote
attacker could potentially exploit this by conducting a
Man-in-the-middle (MITM) attack in order to obtain credentials.
(CVE-2015-0834)

Carsten Book, Christoph Diehl, Gary Kwong, Jan de Mooij, Liz Henry,
Byron Campen, Tom Schuster, Ryan VanderMeulen, Christian Holler, Jesse
Ruderman, Randell Jesup, Robin Whittleton, Jon Coppeard, and Nikhil
Marathe discovered multiple memory safety issues in Firefox. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit these to cause a denial of service via
application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2015-0835, CVE-2015-0836).

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
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/26");
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

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"36.0+build2-0ubuntu0.12.04.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"36.0+build2-0ubuntu0.14.04.4")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"firefox", pkgver:"36.0+build2-0ubuntu0.14.10.4")) flag++;

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
