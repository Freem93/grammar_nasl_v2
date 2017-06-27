#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2417-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79433);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/26 14:16:26 $");

  script_cve_id("CVE-2014-3610", "CVE-2014-3611", "CVE-2014-3645", "CVE-2014-3646", "CVE-2014-3647", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-3690", "CVE-2014-4608", "CVE-2014-7207", "CVE-2014-7975");
  script_bugtraq_id(68214, 70314, 70691, 70742, 70743, 70745, 70746, 70748, 70766, 70867, 70883);
  script_osvdb_id(108489, 113629, 113724, 113726, 113727, 113731, 113823, 113899);
  script_xref(name:"USN", value:"2417-1");

  script_name(english:"Ubuntu 12.04 LTS : linux vulnerabilities (USN-2417-1)");
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
"Nadav Amit reported that the KVM (Kernel Virtual Machine) mishandles
noncanonical addresses when emulating instructions that change the rip
(Instruction Pointer). A guest user with access to I/O or the MMIO can
use this flaw to cause a denial of service (system crash) of the
guest. (CVE-2014-3647)

A flaw was discovered with the handling of the invept instruction in
the KVM (Kernel Virtual Machine) subsystem of the Linux kernel. An
unprivileged guest user could exploit this flaw to cause a denial of
service (system crash) on the guest. (CVE-2014-3646)

A flaw was discovered with invept instruction support when using
nested EPT in the KVM (Kernel Virtual Machine). An unprivileged guest
user could exploit this flaw to cause a denial of service (system
crash) on the guest. (CVE-2014-3645)

Lars Bull reported a race condition in the PIT (programmable interrupt
timer) emulation in the KVM (Kernel Virtual Machine) subsystem of the
Linux kernel. A local guest user with access to PIT i/o ports could
exploit this flaw to cause a denial of service (crash) on the host.
(CVE-2014-3611)

Lars Bull and Nadav Amit reported a flaw in how KVM (the Kernel
Virtual Machine) handles noncanonical writes to certain MSR registers.
A privileged guest user can exploit this flaw to cause a denial of
service (kernel panic) on the host. (CVE-2014-3610)

A flaw in the handling of malformed ASCONF chunks by SCTP (Stream
Control Transmission Protocol) implementation in the Linux kernel was
discovered. A remote attacker could exploit this flaw to cause a
denial of service (system crash). (CVE-2014-3673)

A flaw in the handling of duplicate ASCONF chunks by SCTP (Stream
Control Transmission Protocol) implementation in the Linux kernel was
discovered. A remote attacker could exploit this flaw to cause a
denial of service (panic). (CVE-2014-3687)

It was discovered that excessive queuing by SCTP (Stream Control
Transmission Protocol) implementation in the Linux kernel can cause
memory pressure. A remote attacker could exploit this flaw to cause a
denial of service. (CVE-2014-3688)

A flaw was discovered in how the Linux kernel's KVM (Kernel Virtual
Machine) subsystem handles the CR4 control register at VM entry on
Intel processors. A local host OS user can exploit this to cause a
denial of service (kill arbitrary processes, or system disruption) by
leveraging /dev/kvm access. (CVE-2014-3690)

Don Bailey discovered a flaw in the LZO decompress algorithm used by
the Linux kernel. An attacker could exploit this flaw to cause a
denial of service (memory corruption or OOPS). (CVE-2014-4608)

It was discovered the Linux kernel's implementation of IPv6 did not
properly validate arguments in the ipv6_select_ident function. A local
user could exploit this flaw to cause a denial of service (system
crash) by leveraging tun or macvtap device access. (CVE-2014-7207)

Andy Lutomirski discovered that the Linux kernel was not checking the
CAP_SYS_ADMIN when remounting filesystems to read-only. A local user
could exploit this flaw to cause a denial of service (loss of
writability). (CVE-2014-7975).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-72-generic", pkgver:"3.2.0-72.107")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-72-generic-pae", pkgver:"3.2.0-72.107")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-72-highbank", pkgver:"3.2.0-72.107")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-72-virtual", pkgver:"3.2.0-72.107")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.2-generic / linux-image-3.2-generic-pae / etc");
}
