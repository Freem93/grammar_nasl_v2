#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2969-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91090);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/12/01 21:07:49 $");

  script_cve_id("CVE-2015-7515", "CVE-2015-8830", "CVE-2016-0821", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2188", "CVE-2016-3138", "CVE-2016-3156", "CVE-2016-3157");
  script_osvdb_id(130648, 135157, 135482, 135871, 135872, 135873, 135874, 135875, 135943, 135947);
  script_xref(name:"USN", value:"2969-1");

  script_name(english:"Ubuntu 14.04 LTS : linux-lts-utopic vulnerabilities (USN-2969-1)");
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
"Ralf Spenneberg discovered that the Aiptek Tablet USB device driver in
the Linux kernel did not properly sanity check the endpoints reported
by the device. An attacker with physical access could cause a denial
of service (system crash). (CVE-2015-7515)

Ben Hawkes discovered that the Linux kernel's AIO interface allowed
single writes greater than 2GB, which could cause an integer overflow
when writing to certain filesystems, socket or device types. A local
attacker could this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2015-8830)

Zach Riggle discovered that the Linux kernel's list poison feature did
not take into account the mmap_min_addr value. A local attacker could
use this to bypass the kernel's poison-pointer protection mechanism
while attempting to exploit an existing kernel vulnerability.
(CVE-2016-0821)

Ralf Spenneberg discovered that the USB sound subsystem in the Linux
kernel did not properly validate USB device descriptors. An attacker
with physical access could use this to cause a denial of service
(system crash). (CVE-2016-2184)

Ralf Spenneberg discovered that the ATI Wonder Remote II USB driver in
the Linux kernel did not properly validate USB device descriptors. An
attacker with physical access could use this to cause a denial of
service (system crash). (CVE-2016-2185)

Ralf Spenneberg discovered that the PowerMate USB driver in the Linux
kernel did not properly validate USB device descriptors. An attacker
with physical access could use this to cause a denial of service
(system crash). (CVE-2016-2186)

Ralf Spenneberg discovered that the I/O-Warrior USB device driver in
the Linux kernel did not properly validate USB device descriptors. An
attacker with physical access could use this to cause a denial of
service (system crash). (CVE-2016-2188)

Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered
that the USB abstract device control driver for modems and ISDN
adapters did not validate endpoint descriptors. An attacker with
physical access could use this to cause a denial of service (system
crash). (CVE-2016-3138)

It was discovered that the IPv4 implementation in the Linux kernel did
not perform the destruction of inet device objects properly. An
attacker in a guest OS could use this to cause a denial of service
(networking outage) in the host OS. (CVE-2016-3156)

Andy Lutomirski discovered that the Linux kernel did not properly
context- switch IOPL on 64-bit PV Xen guests. An attacker in a guest
OS could use this to cause a denial of service (guest OS crash), gain
privileges, or obtain sensitive information. (CVE-2016-3157).

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
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");
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

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.16.0-71-generic", pkgver:"3.16.0-71.91~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.16.0-71-generic-lpae", pkgver:"3.16.0-71.91~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.16.0-71-lowlatency", pkgver:"3.16.0-71.91~14.04.1")) flag++;

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
