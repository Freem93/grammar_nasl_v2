#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2372-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78466);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/24 17:37:07 $");

  script_cve_id("CVE-2014-1574", "CVE-2014-1575", "CVE-2014-1576", "CVE-2014-1577", "CVE-2014-1578", "CVE-2014-1580", "CVE-2014-1581", "CVE-2014-1582", "CVE-2014-1583", "CVE-2014-1584", "CVE-2014-1585", "CVE-2014-1586");
  script_bugtraq_id(70424, 70425, 70426, 70427, 70428, 70430, 70431, 70432, 70434, 70436, 70439, 70440);
  script_osvdb_id(113141, 113142, 113143, 113144, 113145, 113146, 113147, 113148, 113149, 113150, 113151, 113152, 113159, 113160, 113161, 113162, 113163, 113165, 113166, 113209);
  script_xref(name:"USN", value:"2372-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS : firefox vulnerabilities (USN-2372-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bobby Holley, Christian Holler, David Bolter, Byron Campen, Jon
Coppeard, Carsten Book, Martijn Wargers, Shih-Chiang Chien, Terrence
Cole and Jeff Walden discovered multiple memory safety issues in
Firefox. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial
of service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2014-1574,
CVE-2014-1575)

Atte Kettunen discovered a buffer overflow during CSS manipulation. If
a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via application crash or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2014-1576)

Holger Fuhrmannek discovered an out-of-bounds read with Web Audio. If
a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to steal sensitive
information. (CVE-2014-1577)

Abhishek Arya discovered an out-of-bounds write when buffering WebM
video in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to cause a denial of service via application crash or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-1578)

Michal Zalewski discovered that memory may not be correctly
initialized when rendering a malformed GIF in to a canvas in some
circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to steal
sensitive information. (CVE-2014-1580)

A use-after-free was discovered during text layout in some
circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash or execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2014-1581)

Patrick McManus and David Keeler discovered 2 issues that could result
in certificate pinning being bypassed in some circumstances. An
attacker with a fraudulent certificate could potentially exploit this
conduct a man in the middle attack. (CVE-2014-1582, CVE-2014-1584)

Eric Shepherd and Jan-Ivar Bruaroey discovered issues with video
sharing via WebRTC in iframes, where video continues to be shared
after being stopped and navigating to a new site doesn't turn off the
camera. An attacker could potentially exploit this to access the
camera without the user being aware. (CVE-2014-1585, CVE-2014-1586)

Boris Zbarsky discovered that webapps could use the Alarm API to read
the values of cross-origin references. If a user were tricked in to
installing a specially crafter webapp, an attacker could potentially
exploit this to bypass same-origin restrictions. (CVE-2014-1583).

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"33.0+build2-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"33.0+build2-0ubuntu0.14.04.1")) flag++;

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
