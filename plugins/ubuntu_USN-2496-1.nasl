#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2496-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81255);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2012-3509", "CVE-2014-8484", "CVE-2014-8485", "CVE-2014-8501", "CVE-2014-8502", "CVE-2014-8503", "CVE-2014-8504", "CVE-2014-8737", "CVE-2014-8738");
  script_bugtraq_id(55281, 70714, 70741, 70761, 70866, 70868, 70869, 70908, 71083);
  script_xref(name:"USN", value:"2496-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 14.04 LTS / 14.10 : binutils vulnerabilities (USN-2496-1)");
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
"Michal Zalewski discovered that the setup_group function in libbfd in
GNU binutils did not properly check group headers in ELF files. An
attacker could use this to craft input that could cause a denial of
service (application crash) or possibly execute arbitrary code.
(CVE-2014-8485)

Hanno Bock discovered that the _bfd_XXi_swap_aouthdr_in function in
libbfd in GNU binutils allowed out-of-bounds writes. An attacker could
use this to craft input that could cause a denial of service
(application crash) or possibly execute arbitrary code.
(CVE-2014-8501)

Hanno Bock discovered a heap-based buffer overflow in the
pe_print_edata function in libbfd in GNU binutils. An attacker could
use this to craft input that could cause a denial of service
(application crash) or possibly execute arbitrary code.
(CVE-2014-8502)

Alexander Cherepanov discovered multiple directory traversal
vulnerabilities in GNU binutils. An attacker could use this to craft
input that could delete arbitrary files. (CVE-2014-8737)

Alexander Cherepanov discovered the _bfd_slurp_extended_name_table
function in libbfd in GNU binutils allowed invalid writes when
handling extended name tables in an archive. An attacker could use
this to craft input that could cause a denial of service (application
crash) or possibly execute arbitrary code. (CVE-2014-8738)

Hanno Bock discovered a stack-based buffer overflow in the ihex_scan
function in libbfd in GNU binutils. An attacker could use this to
craft input that could cause a denial of service (application crash).
(CVE-2014-8503)

Michal Zalewski discovered a stack-based buffer overflow in the
srec_scan function in libbfd in GNU binutils. An attacker could use
this to to craft input that could cause a denial of service
(application crash); the GNU C library's Fortify Source printf
protection should prevent the possibility of executing arbitrary code.
(CVE-2014-8504)

Michal Zalewski discovered that the srec_scan function in libbfd in
GNU binutils allowed out-of-bounds reads. An attacker could use this
to craft input to cause a denial of service. This issue only affected
Ubuntu 14.04 LTS, Ubuntu 12.04 LTS, and Ubuntu 10.04 LTS.
(CVE-2014-8484)

Sang Kil Cha discovered multiple integer overflows in the
_objalloc_alloc function and objalloc_alloc macro in binutils. This
could allow an attacker to cause a denial of service (application
crash). This issue only affected Ubuntu 12.04 LTS and Ubuntu 10.04
LTS. (CVE-2012-3509)

Alexander Cherepanov and Hanno Bock discovered multiple additional
out-of-bounds reads and writes in GNU binutils. An attacker could use
these to craft input that could cause a denial of service (application
crash) or possibly execute arbitrary code. A few of these issues may
be limited in exposure to a denial of service (application abort) by
the GNU C library's Fortify Source printf protection.

The strings(1) utility in GNU binutils used libbfd by default when
examining executable object files; unfortunately, libbfd was not
originally developed with the expectation of hostile input. As a
defensive measure, the behavior of strings has been changed to default
to 'strings --all' behavior, which does not use libbfd; use the new
argument to strings, '--data', to recreate the old behavior.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected binutils and / or binutils-multiarch packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/10");
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
if (! ereg(pattern:"^(10\.04|12\.04|14\.04|14\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 14.04 / 14.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"binutils", pkgver:"2.20.1-3ubuntu7.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"binutils-multiarch", pkgver:"2.20.1-3ubuntu7.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"binutils", pkgver:"2.22-6ubuntu1.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"binutils-multiarch", pkgver:"2.22-6ubuntu1.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"binutils", pkgver:"2.24-5ubuntu3.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"binutils-multiarch", pkgver:"2.24-5ubuntu3.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"binutils", pkgver:"2.24.90.20141014-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"binutils-multiarch", pkgver:"2.24.90.20141014-0ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / binutils-multiarch");
}
