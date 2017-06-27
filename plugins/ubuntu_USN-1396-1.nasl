#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1396-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58318);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/25 16:11:45 $");

  script_cve_id("CVE-2009-5029", "CVE-2010-0015", "CVE-2011-1071", "CVE-2011-1089", "CVE-2011-1095", "CVE-2011-1658", "CVE-2011-1659", "CVE-2011-2702", "CVE-2011-4609", "CVE-2012-0864");
  script_bugtraq_id(37885, 46563, 46740, 47370, 50898, 51439, 52201);
  script_osvdb_id(61791, 66751, 72796, 73407, 74883, 75261, 77508, 78316, 80718, 80719);
  script_xref(name:"USN", value:"1396-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 / 11.10 : eglibc, glibc vulnerabilities (USN-1396-1)");
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
"It was discovered that the GNU C Library did not properly handle
integer overflows in the timezone handling code. An attacker could use
this to possibly execute arbitrary code by convincing an application
to load a maliciously constructed tzfile. (CVE-2009-5029)

It was discovered that the GNU C Library did not properly handle
passwd.adjunct.byname map entries in the Network Information Service
(NIS) code in the name service caching daemon (nscd). An attacker
could use this to obtain the encrypted passwords of NIS accounts. This
issue only affected Ubuntu 8.04 LTS. (CVE-2010-0015)

Chris Evans reported that the GNU C Library did not properly calculate
the amount of memory to allocate in the fnmatch() code. An attacker
could use this to cause a denial of service or possibly execute
arbitrary code via a maliciously crafted UTF-8 string. This issue only
affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS and Ubuntu 10.10.
(CVE-2011-1071)

Tomas Hoger reported that an additional integer overflow was possible
in the GNU C Library fnmatch() code. An attacker could use this to
cause a denial of service via a maliciously crafted UTF-8 string. This
issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS, Ubuntu 10.10
and Ubuntu 11.04. (CVE-2011-1659)

Dan Rosenberg discovered that the addmntent() function in the GNU C
Library did not report an error status for failed attempts to write to
the /etc/mtab file. This could allow an attacker to corrupt /etc/mtab,
possibly causing a denial of service or otherwise manipulate mount
options. This issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS,
Ubuntu 10.10 and Ubuntu 11.04. (CVE-2011-1089)

Harald van Dijk discovered that the locale program included with the
GNU C library did not properly quote its output. This could allow a
local attacker to possibly execute arbitrary code using a crafted
localization string that was evaluated in a shell script. This issue
only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS and Ubuntu 10.10.
(CVE-2011-1095)

It was discovered that the GNU C library loader expanded the $ORIGIN
dynamic string token when RPATH is composed entirely of this token.
This could allow an attacker to gain privilege via a setuid program
that had this RPATH value. (CVE-2011-1658)

It was discovered that the GNU C library implementation of memcpy
optimized for Supplemental Streaming SIMD Extensions 3 (SSSE3)
contained a possible integer overflow. An attacker could use this to
cause a denial of service or possibly execute arbitrary code. This
issue only affected Ubuntu 10.04 LTS. (CVE-2011-2702)

John Zimmerman discovered that the Remote Procedure Call (RPC)
implementation in the GNU C Library did not properly handle large
numbers of connections. This could allow a remote attacker to cause a
denial of service. (CVE-2011-4609)

It was discovered that the GNU C Library vfprintf() implementation
contained a possible integer overflow in the format string protection
code offered by FORTIFY_SOURCE. An attacker could use this flaw in
conjunction with a format string vulnerability to bypass the format
string protection and possibly execute arbitrary code. (CVE-2012-0864).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libc-bin and / or libc6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2016 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|10\.04|10\.10|11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 10.10 / 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libc6", pkgver:"2.7-10ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc-bin", pkgver:"2.11.1-0ubuntu7.10")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libc6", pkgver:"2.11.1-0ubuntu7.10")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libc-bin", pkgver:"2.12.1-0ubuntu10.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libc6", pkgver:"2.12.1-0ubuntu10.4")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libc6", pkgver:"2.13-0ubuntu13.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libc6", pkgver:"2.13-20ubuntu5.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libc-bin / libc6");
}
