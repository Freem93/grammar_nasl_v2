#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2038-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71205);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/26 14:16:25 $");

  script_cve_id("CVE-2013-0343", "CVE-2013-2140", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-2893", "CVE-2013-2895", "CVE-2013-2896", "CVE-2013-2897", "CVE-2013-2899", "CVE-2013-4350", "CVE-2013-4387");
  script_bugtraq_id(58795, 60414, 62042, 62043, 62044, 62045, 62046, 62048, 62049, 62050, 62405, 62696);
  script_osvdb_id(90811, 94031, 96766, 96767, 96768, 96770, 96771, 96772, 96774, 96775, 97569, 97888);
  script_xref(name:"USN", value:"2038-1");

  script_name(english:"Ubuntu 12.04 LTS : linux vulnerabilities (USN-2038-1)");
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
"An information leak was discovered in the handling of ICMPv6 Router
Advertisement (RA) messages in the Linux kernel's IPv6 network stack.
A remote attacker could exploit this flaw to cause a denial of service
(excessive retries and address-generation outage), and consequently
obtain sensitive information. (CVE-2013-0343)

A flaw was discovered in the Xen subsystem of the Linux kernel when it
provides read-only access to a disk that supports TRIM or SCSI UNMAP
to a guest OS. A privileged user in the guest OS could exploit this
flaw to destroy data on the disk, even though the guest OS should not
be able to write to the disk. (CVE-2013-2140)

Kees Cook discovered flaw in the Human Interface Device (HID)
subsystem of the Linux kernel. A physically proximate attacker could
exploit this flaw to execute arbitrary code or cause a denial of
service (heap memory corruption) via a specially crafted device that
provides an invalid Report ID. (CVE-2013-2888)

Kees Cook discovered flaw in the Human Interface Device (HID)
subsystem when CONFIG_HID_ZEROPLUS is enabled. A physically proximate
attacker could leverage this flaw to cause a denial of service via a
specially crafted device. (CVE-2013-2889)

Kees Cook discovered a flaw in the Human Interface Device (HID)
subsystem of the Linux kerenl when CONFIG_HID_PANTHERLORD is enabled.
A physically proximate attacker could cause a denial of service (heap
out-of-bounds write) via a specially crafted device. (CVE-2013-2892)

Kees Cook discovered another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when any of CONFIG_LOGITECH_FF,
CONFIG_LOGIG940_FF, or CONFIG_LOGIWHEELS_FF are enabled. A physcially
proximate attacker can leverage this flaw to cause a denial of service
vias a specially crafted device. (CVE-2013-2893)

Kees Cook discovered another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when CONFIG_HID_LOGITECH_DJ is enabled.
A physically proximate attacker could cause a denial of service (OOPS)
or obtain sensitive information from kernel memory via a specially
crafted device. (CVE-2013-2895)

Kees Cook discovered a vulnerability in the Linux Kernel's Human
Interface Device (HID) subsystem's support for N-Trig touch screens. A
physically proximate attacker could exploit this flaw to cause a
denial of service (OOPS) via a specially crafted device.
(CVE-2013-2896)

Kees Cook discovered yet another flaw in the Human Interface Device
(HID) subsystem of the Linux kernel when CONFIG_HID_MULTITOUCH is
enabled. A physically proximate attacker could leverage this flaw to
cause a denial of service (OOPS) via a specially crafted device.
(CVE-2013-2897)

Kees Cook discovered a flaw in the Human Interface Device (HID)
subsystem of the Linux kernel whe CONFIG_HID_PICOLCD is enabled. A
physically proximate attacker could exploit this flaw to cause a
denial of service (OOPS) via a specially crafted device.
(CVE-2013-2899)

Alan Chester reported a flaw in the IPv6 Stream Control Transmission
Protocol (SCTP) of the Linux kernel. A remote attacker could exploit
this flaw to obtain sensitive information by sniffing network traffic.
(CVE-2013-4350)

Dmitry Vyukov reported a flaw in the Linux kernel's handling of IPv6
UDP Fragmentation Offload (UFO) processing. A remote attacker could
leverage this flaw to cause a denial of service (system crash).
(CVE-2013-4387).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-57-generic", pkgver:"3.2.0-57.87")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-57-generic-pae", pkgver:"3.2.0-57.87")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-57-highbank", pkgver:"3.2.0-57.87")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-57-virtual", pkgver:"3.2.0-57.87")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.2-generic / linux-image-3.2-generic-pae / etc");
}
