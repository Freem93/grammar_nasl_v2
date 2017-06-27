#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2326-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77485);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/09/06 13:33:34 $");

  script_cve_id("CVE-2014-3168", "CVE-2014-3169", "CVE-2014-3171", "CVE-2014-3173", "CVE-2014-3174", "CVE-2014-3175");
  script_bugtraq_id(69398, 69402, 69403, 69405, 69406, 69407);
  script_osvdb_id(110508, 110540);
  script_xref(name:"USN", value:"2326-1");

  script_name(english:"Ubuntu 14.04 LTS : oxide-qt vulnerabilities (USN-2326-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A use-after-free was discovered in the SVG implementation in Blink. If
a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via renderer crash, or execute arbitrary code with the privileges of
the sandboxed render process. (CVE-2014-3168)

A use-after-free was discovered in the DOM implementation in Blink. If
a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via renderer crash, or execute arbitrary code with the privileges of
the sandboxed render process. (CVE-2014-3169)

A use-after-free was discovered in V8. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash, or
execute arbitrary code with the privileges of the sandboxed render
process. (CVE-2014-3171)

It was discovered that WebGL clear calls did not interact properly
with the state of a draw buffer. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit
this to cause a denial of service. (CVE-2014-3173)

A threading issue was discovered in the Web Audio API during attempts
to update biquad filter coefficients. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service. (CVE-2014-3174)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2014-3175).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected liboxideqtcore0, oxideqt-codecs and / or
oxideqt-codecs-extra packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/03");
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
if (! ereg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.1.2-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"oxideqt-codecs", pkgver:"1.1.2-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"oxideqt-codecs-extra", pkgver:"1.1.2-0ubuntu0.14.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "liboxideqtcore0 / oxideqt-codecs / oxideqt-codecs-extra");
}
