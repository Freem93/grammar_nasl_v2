#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2243-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74493);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/24 17:29:03 $");

  script_cve_id("CVE-2014-1533", "CVE-2014-1534", "CVE-2014-1536", "CVE-2014-1537", "CVE-2014-1538", "CVE-2014-1540", "CVE-2014-1541", "CVE-2014-1542");
  script_bugtraq_id(67964, 67966, 67968, 67971, 67978);
  script_osvdb_id(107904, 107905, 107906);
  script_xref(name:"USN", value:"2243-1");

  script_name(english:"Ubuntu 12.04 LTS / 13.10 / 14.04 LTS : firefox vulnerabilities (USN-2243-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Gary Kwong, Christoph Diehl, Christian Holler, Hannes Verschore, Jan
de Mooij, Ryan VanderMeulen, Jeff Walden, Kyle Huey, Jesse Ruderman,
Gregor Wagner, Benoit Jacob and Karl Tomlinson discovered multiple
memory safety issues in Firefox. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit
these to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-1533, CVE-2014-1534)

Abhishek Arya discovered multiple use-after-free and out-of-bounds
read issues in Firefox. An attacker could potentially exploit these to
cause a denial of service via application crash or execute arbitrary
code with the priviliges of the user invoking Firefox. (CVE-2014-1536,
CVE-2014-1537, CVE-2014-1538)

Tyson Smith and Jesse Schwartzentruber discovered a use-after-free in
the event listener manager. An attacker could potentially exploit this
to cause a denial of service via application crash or execute
arbitrary code with the priviliges of the user invoking Firefox.
(CVE-2014-1540)

A use-after-free was discovered in the SMIL animation controller. An
attacker could potentially exploit this to cause a denial of service
via application crash or execute arbitrary code with the priviliges of
the user invoking Firefox. (CVE-2014-1541)

Holger Fuhrmannek discovered a buffer overflow in Web Audio. An
attacker could potentially exploit this to cause a denial of service
via application crash or execute arbitrary code with the priviliges of
the user invoking Firefox. (CVE-2014-1542).

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
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/12");
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
if (! ereg(pattern:"^(12\.04|13\.10|14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 13.10 / 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"30.0+build1-0ubuntu0.12.04.3")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"firefox", pkgver:"30.0+build1-0ubuntu0.13.10.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"30.0+build1-0ubuntu0.14.04.3")) flag++;

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
