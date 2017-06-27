#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2667-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84618);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/26 14:25:59 $");

  script_cve_id("CVE-2015-1420", "CVE-2015-4001", "CVE-2015-4002", "CVE-2015-4003");
  script_osvdb_id(117759, 122241, 122242, 122243, 122244);
  script_xref(name:"USN", value:"2667-1");

  script_name(english:"Ubuntu 15.04 : linux vulnerabilities (USN-2667-1)");
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
"A race condition was discovered in the Linux kernel's file_handle size
verification. A local user could exploit this flaw to read potentially
sensative memory locations. (CVE-2015-1420)

A underflow error was discovered in the Linux kernel's Ozmo Devices
USB over WiFi host controller driver. A remote attacker could exploit
this flaw to cause a denial of service (system crash) or potentially
execute arbitrary code via a specially crafted packet. (CVE-2015-4001)

A bounds check error was discovered in the Linux kernel's Ozmo Devices
USB over WiFi host controller driver. A remote attacker could exploit
this flaw to cause a denial of service (system crash) or potentially
execute arbitrary code via a specially crafted packet. (CVE-2015-4002)

A division by zero error was discovered in the Linux kernel's Ozmo
Devices USB over WiFi host controller driver. A remote attacker could
exploit this flaw to cause a denial of service (system crash).
(CVE-2015-4003).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.19-generic,
linux-image-3.19-generic-lpae and / or linux-image-3.19-lowlatency
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.19-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.19-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.19-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/08");
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
if (! ereg(pattern:"^(15\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 15.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"15.04", pkgname:"linux-image-3.19.0-22-generic", pkgver:"3.19.0-22.22")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"linux-image-3.19.0-22-generic-lpae", pkgver:"3.19.0-22.22")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"linux-image-3.19.0-22-lowlatency", pkgver:"3.19.0-22.22")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.19-generic / linux-image-3.19-generic-lpae / etc");
}
