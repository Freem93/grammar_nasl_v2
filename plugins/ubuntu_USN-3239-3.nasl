#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3239-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97936);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/28 13:31:43 $");

  script_cve_id("CVE-2015-8982", "CVE-2015-8983", "CVE-2015-8984", "CVE-2016-1234", "CVE-2016-3706", "CVE-2016-4429", "CVE-2016-5417", "CVE-2016-6323");
  script_osvdb_id(98836, 118304, 118309);
  script_xref(name:"USN", value:"3239-3");

  script_name(english:"Ubuntu 12.04 LTS : eglibc regression (USN-3239-3)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-3239-1 fixed vulnerabilities in the GNU C Library. Unfortunately,
the fix for CVE-2016-3706 introduced a regression that in some
circumstances prevented IPv6 addresses from resolving. This update
reverts the change in Ubuntu 12.04 LTS. We apologize for the error.

It was discovered that the GNU C Library incorrectly handled the
strxfrm() function. An attacker could use this issue to cause a denial
of service or possibly execute arbitrary code. This issue only
affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2015-8982)

It was discovered that an integer overflow existed in the
_IO_wstr_overflow() function of the GNU C Library. An
attacker could use this to cause a denial of service or
possibly execute arbitrary code. This issue only affected
Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2015-8983)

It was discovered that the fnmatch() function in the GNU C
Library did not properly handle certain malformed patterns.
An attacker could use this to cause a denial of service.
This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04
LTS. (CVE-2015-8984)

Alexander Cherepanov discovered a stack-based buffer
overflow in the glob implementation of the GNU C Library. An
attacker could use this to specially craft a directory
layout and cause a denial of service. (CVE-2016-1234)

Michael Petlan discovered an unbounded stack allocation in
the getaddrinfo() function of the GNU C Library. An attacker
could use this to cause a denial of service. (CVE-2016-3706)

Aldy Hernandez discovered an unbounded stack allocation in
the sunrpc implementation in the GNU C Library. An attacker
could use this to cause a denial of service. (CVE-2016-4429)

Tim Ruehsen discovered that the getaddrinfo() implementation
in the GNU C Library did not properly track memory
allocations. An attacker could use this to cause a denial of
service. This issue only affected Ubuntu 16.04 LTS.
(CVE-2016-5417)

Andreas Schwab discovered that the GNU C Library on ARM
32-bit platforms did not properly set up execution contexts.
An attacker could use this to cause a denial of service.
(CVE-2016-6323).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected libc6 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017 Canonical, Inc. / NASL script (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libc6", pkgver:"2.15-0ubuntu10.18")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libc6");
}
