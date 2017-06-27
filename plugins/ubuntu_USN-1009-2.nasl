#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1009-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51501);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2010-3847", "CVE-2010-3856", "CVE-2011-0536");
  script_bugtraq_id(44154, 44347);
  script_osvdb_id(68721);
  script_xref(name:"USN", value:"1009-2");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : eglibc, glibc vulnerability (USN-1009-2)");
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
"USN-1009-1 fixed vulnerabilities in the GNU C library. Colin Watson
discovered that the fixes were incomplete and introduced flaws with
setuid programs loading libraries that used dynamic string tokens in
their RPATH. If the 'man' program was installed setuid, a local
attacker could exploit this to gain 'man' user privileges, potentially
leading to further privilege escalations. Default Ubuntu installations
were not affected.

Tavis Ormandy discovered multiple flaws in the GNU C Library's
handling of the LD_AUDIT environment variable when running a
privileged binary. A local attacker could exploit this to gain root
privileges. (CVE-2010-3847, CVE-2010-3856).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eglibc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:glibc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:glibc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-prof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"glibc-doc", pkgver:"2.7-10ubuntu8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"glibc-source", pkgver:"2.7-10ubuntu8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6", pkgver:"2.7-10ubuntu8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-amd64", pkgver:"2.7-10ubuntu8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-dbg", pkgver:"2.7-10ubuntu8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-dev", pkgver:"2.7-10ubuntu8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-dev-amd64", pkgver:"2.7-10ubuntu8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-dev-i386", pkgver:"2.7-10ubuntu8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-i386", pkgver:"2.7-10ubuntu8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-i686", pkgver:"2.7-10ubuntu8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-pic", pkgver:"2.7-10ubuntu8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-prof", pkgver:"2.7-10ubuntu8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libc6-xen", pkgver:"2.7-10ubuntu8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nscd", pkgver:"2.7-10ubuntu8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"eglibc-source", pkgver:"2.10.1-0ubuntu19")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"glibc-doc", pkgver:"2.10.1-0ubuntu19")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc-bin", pkgver:"2.10.1-0ubuntu19")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc-dev-bin", pkgver:"2.10.1-0ubuntu19")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6", pkgver:"2.10.1-0ubuntu19")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-amd64", pkgver:"2.10.1-0ubuntu19")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-dbg", pkgver:"2.10.1-0ubuntu19")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-dev", pkgver:"2.10.1-0ubuntu19")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-dev-amd64", pkgver:"2.10.1-0ubuntu19")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-dev-i386", pkgver:"2.10.1-0ubuntu19")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-i386", pkgver:"2.10.1-0ubuntu19")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-i686", pkgver:"2.10.1-0ubuntu19")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-pic", pkgver:"2.10.1-0ubuntu19")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-prof", pkgver:"2.10.1-0ubuntu19")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libc6-xen", pkgver:"2.10.1-0ubuntu19")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"nscd", pkgver:"2.10.1-0ubuntu19")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"eglibc-source", pkgver:"2.11.1-0ubuntu7.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"glibc-doc", pkgver:"2.11.1-0ubuntu7.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc-bin", pkgver:"2.11.1-0ubuntu7.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc-dev-bin", pkgver:"2.11.1-0ubuntu7.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6", pkgver:"2.11.1-0ubuntu7.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-amd64", pkgver:"2.11.1-0ubuntu7.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-dbg", pkgver:"2.11.1-0ubuntu7.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-dev", pkgver:"2.11.1-0ubuntu7.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-dev-amd64", pkgver:"2.11.1-0ubuntu7.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-dev-i386", pkgver:"2.11.1-0ubuntu7.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-i386", pkgver:"2.11.1-0ubuntu7.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-i686", pkgver:"2.11.1-0ubuntu7.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-pic", pkgver:"2.11.1-0ubuntu7.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-prof", pkgver:"2.11.1-0ubuntu7.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6-xen", pkgver:"2.11.1-0ubuntu7.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"nscd", pkgver:"2.11.1-0ubuntu7.7")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"eglibc-source", pkgver:"2.12.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"glibc-doc", pkgver:"2.12.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libc-bin", pkgver:"2.12.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libc-dev-bin", pkgver:"2.12.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libc6", pkgver:"2.12.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libc6-amd64", pkgver:"2.12.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libc6-dbg", pkgver:"2.12.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libc6-dev", pkgver:"2.12.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libc6-dev-amd64", pkgver:"2.12.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libc6-dev-i386", pkgver:"2.12.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libc6-i386", pkgver:"2.12.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libc6-pic", pkgver:"2.12.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libc6-prof", pkgver:"2.12.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libc6-xen", pkgver:"2.12.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"nscd", pkgver:"2.12.1-0ubuntu10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "eglibc-source / glibc-doc / glibc-source / libc-bin / libc-dev-bin / etc");
}
