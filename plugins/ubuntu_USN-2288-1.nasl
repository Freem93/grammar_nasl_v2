#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2288-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76567);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/04/10 13:19:30 $");

  script_cve_id("CVE-2014-1739", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3940", "CVE-2014-4608", "CVE-2014-4611", "CVE-2014-4943");
  script_bugtraq_id(67309, 67321, 67786, 68048, 68214, 68218, 68683);
  script_osvdb_id(106969, 107650, 107819, 108489);
  script_xref(name:"USN", value:"2288-1");

  script_name(english:"Ubuntu 12.04 LTS : linux-lts-trusty vulnerabilities (USN-2288-1)");
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
"Sasha Levin reported a flaw in the Linux kernel's point-to-point
protocol (PPP) when used with the Layer Two Tunneling Protocol (L2TP).
A local user could exploit this flaw to gain administrative
privileges. (CVE-2014-4943)

Salva Peiro discovered an information leak in the Linux kernel's
media- device driver. A local attacker could exploit this flaw to
obtain sensitive information from kernel memory. (CVE-2014-1739)

A bounds check error was discovered in the socket filter subsystem of
the Linux kernel. A local user could exploit this flaw to cause a
denial of service (system crash) via crafted BPF instructions.
(CVE-2014-3144)

A remainder calculation error was discovered in the socket filter
subsystem of the Linux kernel. A local user could exploit this flaw to
cause a denial of service (system crash) via crafted BPF instructions.
(CVE-2014-3145)

A flaw was discovered in the Linux kernel's handling of hugetlb
entries. A local user could exploit this flaw to cause a denial
service (memory corruption or system crash). (CVE-2014-3940)

Don Bailey discovered a flaw in the LZO decompress algorithm used by
the Linux kernel. An attacker could exploit this flaw to cause a
denial of service (memory corruption or OOPS). (CVE-2014-4608)

Don Bailey and Ludvig Strigeus discovered an integer overflow in the
Linux kernel's implementation of the LZ4 decompression algorithm, when
used by code not complying with API limitations. An attacker could
exploit this flaw to cause a denial of service (memory corruption) or
possibly other unspecified impact. (CVE-2014-4611).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.13-generic and / or
linux-image-3.13-generic-lpae packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2017 Canonical, Inc. / NASL script (C) 2014-2017 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.13.0-32-generic", pkgver:"3.13.0-32.57~precise1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.13.0-32-generic-lpae", pkgver:"3.13.0-32.57~precise1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.13-generic / linux-image-3.13-generic-lpae");
}
