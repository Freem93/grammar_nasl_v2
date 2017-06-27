#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2985-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91334);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/01 21:07:49 $");

  script_cve_id("CVE-2013-2207", "CVE-2014-8121", "CVE-2014-9761", "CVE-2015-1781", "CVE-2015-5277", "CVE-2015-8776", "CVE-2015-8777", "CVE-2015-8778", "CVE-2015-8779", "CVE-2016-2856", "CVE-2016-3075");
  script_osvdb_id(98105, 119253, 121105, 127768, 133568, 133572, 133574, 133577, 133580, 134903, 135494, 137999);
  script_xref(name:"USN", value:"2985-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 : eglibc, glibc vulnerabilities (USN-2985-1)");
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
"Martin Carpenter discovered that pt_chown in the GNU C Library did not
properly check permissions for tty files. A local attacker could use
this to gain administrative privileges or expose sensitive
information. (CVE-2013-2207, CVE-2016-2856)

Robin Hack discovered that the Name Service Switch (NSS)
implementation in the GNU C Library did not properly manage its file
descriptors. An attacker could use this to cause a denial of service
(infinite loop). (CVE-2014-8121)

Joseph Myers discovered that the GNU C Library did not properly handle
long arguments to functions returning a representation of Not a Number
(NaN). An attacker could use this to cause a denial of service (stack
exhaustion leading to an application crash) or possibly execute
arbitrary code. (CVE-2014-9761)

Arjun Shankar discovered that in certain situations the nss_dns code
in the GNU C Library did not properly account buffer sizes when passed
an unaligned buffer. An attacker could use this to cause a denial of
service or possibly execute arbitrary code. (CVE-2015-1781)

Sumit Bose and Lukas Slebodnik discovered that the Name Service Switch
(NSS) implementation in the GNU C Library did not handle long lines in
the files databases correctly. A local attacker could use this to
cause a denial of service (application crash) or possibly execute
arbitrary code. (CVE-2015-5277)

Adam Nielsen discovered that the strftime function in the GNU C
Library did not properly handle out-of-range argument data. An
attacker could use this to cause a denial of service (application
crash) or possibly expose sensitive information. (CVE-2015-8776)

Hector Marco and Ismael Ripoll discovered that the GNU C Library
allowed the pointer-guarding protection mechanism to be disabled by
honoring the LD_POINTER_GUARD environment variable across privilege
boundaries. A local attacker could use this to exploit an existing
vulnerability more easily. (CVE-2015-8777)

Szabolcs Nagy discovered that the hcreate functions in the GNU C
Library did not properly check its size argument, leading to an
integer overflow. An attacker could use to cause a denial of service
(application crash) or possibly execute arbitrary code.
(CVE-2015-8778)

Maksymilian Arciemowicz discovered a stack-based buffer overflow in
the catopen function in the GNU C Library when handling long catalog
names. An attacker could use this to cause a denial of service
(application crash) or possibly execute arbitrary code.
(CVE-2015-8779)

Florian Weimer discovered that the getnetbyname implementation in the
GNU C Library did not properly handle long names passed as arguments.
An attacker could use to cause a denial of service (stack exhaustion
leading to an application crash). (CVE-2016-3075).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libc6 and / or libc6-dev packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/26");
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

if (ubuntu_check(osver:"12.04", pkgname:"libc6", pkgver:"2.15-0ubuntu10.14")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libc6-dev", pkgver:"2.15-0ubuntu10.14")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libc6", pkgver:"2.19-0ubuntu6.8")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libc6-dev", pkgver:"2.19-0ubuntu6.8")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libc6", pkgver:"2.21-0ubuntu4.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libc6-dev", pkgver:"2.21-0ubuntu4.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libc6 / libc6-dev");
}
