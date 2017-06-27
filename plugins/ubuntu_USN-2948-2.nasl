#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2948-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90507);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/26 14:26:00 $");

  script_cve_id("CVE-2015-7566", "CVE-2015-7833", "CVE-2015-8812", "CVE-2016-0723", "CVE-2016-2085", "CVE-2016-2550", "CVE-2016-2782", "CVE-2016-2847");
  script_xref(name:"USN", value:"2948-2");

  script_name(english:"Ubuntu 14.04 LTS : linux-lts-utopic regression (USN-2948-2)");
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
"USN-2948-1 fixed vulnerabilities in the Ubuntu 14.10 Linux kernel
backported to Ubuntu 14.04 LTS. An incorrect reference counting fix in
the radeon driver introduced a regression that could cause a system
crash. This update fixes the problem.

We apologize for the inconvenience.

Ralf Spenneberg discovered that the USB driver for Clie devices in the
Linux kernel did not properly sanity check the endpoints reported by
the device. An attacker with physical access could cause a denial of
service (system crash). (CVE-2015-7566)

Ralf Spenneberg discovered that the usbvision driver in the
Linux kernel did not properly sanity check the interfaces
and endpoints reported by the device. An attacker with
physical access could cause a denial of service (system
crash). (CVE-2015-7833)

Venkatesh Pottem discovered a use-after-free vulnerability
in the Linux kernel's CXGB3 driver. A local attacker could
use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2015-8812)

It was discovered that a race condition existed in the ioctl
handler for the TTY driver in the Linux kernel. A local
attacker could use this to cause a denial of service (system
crash) or expose sensitive information. (CVE-2016-0723)

Xiaofei Rex Guo discovered a timing side channel
vulnerability in the Linux Extended Verification Module
(EVM). An attacker could use this to affect system
integrity. (CVE-2016-2085)

David Herrmann discovered that the Linux kernel incorrectly
accounted file descriptors to the original opener for
in-flight file descriptors sent over a unix domain socket. A
local attacker could use this to cause a denial of service
(resource exhaustion). (CVE-2016-2550)

Ralf Spenneberg discovered that the USB driver for Treo
devices in the Linux kernel did not properly sanity check
the endpoints reported by the device. An attacker with
physical access could cause a denial of service (system
crash). (CVE-2016-2782)

It was discovered that the Linux kernel did not enforce
limits on the amount of data allocated to buffer pipes. A
local attacker could use this to cause a denial of service
(resource exhaustion). (CVE-2016-2847).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.16-generic,
linux-image-3.16-generic-lpae and / or linux-image-3.16-lowlatency
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");
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
if (! ereg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.16.0-70-generic", pkgver:"3.16.0-70.90~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.16.0-70-generic-lpae", pkgver:"3.16.0-70.90~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.16.0-70-lowlatency", pkgver:"3.16.0-70.90~14.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.16-generic / linux-image-3.16-generic-lpae / etc");
}
