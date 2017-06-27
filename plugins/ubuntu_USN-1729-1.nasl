#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1729-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64698);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/25 16:27:05 $");

  script_cve_id("CVE-2013-0765", "CVE-2013-0772", "CVE-2013-0773", "CVE-2013-0774", "CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0777", "CVE-2013-0778", "CVE-2013-0779", "CVE-2013-0780", "CVE-2013-0781", "CVE-2013-0782", "CVE-2013-0783", "CVE-2013-0784");
  script_osvdb_id(90418, 90419, 90420, 90421, 90422, 90423, 90424, 90425, 90426, 90427, 90428, 90429, 90430, 90431);
  script_xref(name:"USN", value:"1729-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.10 / 12.04 LTS / 12.10 : firefox vulnerabilities (USN-1729-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Olli Pettay, Christoph Diehl, Gary Kwong, Jesse Ruderman, Andrew
McCreight, Joe Drew, Wayne Mery, Alon Zakai, Christian Holler, Gary
Kwong, Luke Wagner, Terrence Cole, Timothy Nikkel, Bill McCloskey, and
Nicolas Pierron discovered multiple memory safety issues affecting
Firefox. If the user were tricked into opening a specially crafted
page, an attacker could possibly exploit these to cause a denial of
service via application crash. (CVE-2013-0783, CVE-2013-0784)

Atte Kettunen discovered that Firefox could perform an out-of-bounds
read while rendering GIF format images. An attacker could exploit this
to crash Firefox. (CVE-2013-0772)

Boris Zbarsky discovered that Firefox did not properly handle some
wrapped WebIDL objects. If the user were tricked into opening a
specially crafted page, an attacker could possibly exploit this to
cause a denial of service via application crash, or potentially
execute code with the privileges of the user invoking Firefox.
(CVE-2013-0765)

Bobby Holley discovered vulnerabilities in Chrome Object Wrappers
(COW) and System Only Wrappers (SOW). If a user were tricked into
opening a specially crafted page, a remote attacker could exploit this
to bypass security protections to obtain sensitive information or
potentially execute code with the privileges of the user invoking
Firefox. (CVE-2013-0773)

Frederik Braun that Firefox made the location of the active browser
profile available to JavaScript workers. (CVE-2013-0774)

A use-after-free vulnerability was discovered in Firefox. An attacker
could potentially exploit this to execute code with the privileges of
the user invoking Firefox. (CVE-2013-0775)

Michal Zalewski discovered that Firefox would not always show the
correct address when cancelling a proxy authentication prompt. A
remote attacker could exploit this to conduct URL spoofing and
phishing attacks. (CVE-2013-0776)

Abhishek Arya discovered several problems related to memory handling.
If the user were tricked into opening a specially crafted page, an
attacker could possibly exploit these to cause a denial of service via
application crash, or potentially execute code with the privileges of
the user invoking Firefox. (CVE-2013-0777, CVE-2013-0778,
CVE-2013-0779, CVE-2013-0780, CVE-2013-0781, CVE-2013-0782).

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
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|11\.10|12\.04|12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.10 / 12.04 / 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"firefox", pkgver:"19.0+build1-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"firefox", pkgver:"19.0+build1-0ubuntu0.11.10.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"19.0+build1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"firefox", pkgver:"19.0+build1-0ubuntu0.12.10.1")) flag++;

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
