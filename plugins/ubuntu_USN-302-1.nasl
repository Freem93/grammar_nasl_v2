#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-302-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27877);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/01 21:07:49 $");

  script_cve_id("CVE-2006-0038", "CVE-2006-0744", "CVE-2006-1055", "CVE-2006-1056", "CVE-2006-1522", "CVE-2006-1527", "CVE-2006-1528", "CVE-2006-1855", "CVE-2006-1856", "CVE-2006-1857", "CVE-2006-1858", "CVE-2006-1859", "CVE-2006-1860", "CVE-2006-1863", "CVE-2006-1864", "CVE-2006-2071", "CVE-2006-2271", "CVE-2006-2272", "CVE-2006-2274", "CVE-2006-2275", "CVE-2006-2444");
  script_bugtraq_id(17600, 18081);
  script_osvdb_id(24040, 24443, 24507, 24639, 24746, 24807, 25067, 25139, 25229, 25425, 25632, 25633, 25695, 25696, 25744, 25745, 25746, 25747, 25750, 26615, 26616);
  script_xref(name:"USN", value:"302-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : linux-source-2.6.10/2.6.12/2.6.15 vulnerabilities (USN-302-1)");
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
"An integer overflow was discovered in the do_replace() function. A
local user process with the CAP_NET_ADMIN capability could exploit
this to execute arbitrary commands with full root privileges. However,
none of Ubuntu's supported packages use this capability with any
non-root user, so this only affects you if you use some third party
software like the OpenVZ virtualization system. (CVE-2006-0038)

On EMT64 CPUs, the kernel did not properly handle uncanonical return
addresses. A local user could exploit this to trigger a kernel crash.
(CVE-2006-0744)

Al Viro discovered a local Denial of Service in the sysfs write buffer
handling. By writing a block with a length exactly equal to the
processor's page size to any writable file in /sys, a local attacker
could cause a kernel crash. (CVE-2006-1055)

Jan Beulich discovered an information leak in the handling of
registers for the numeric coprocessor when running on AMD processors.
This allowed processes to see the coprocessor execution state of other
processes, which could reveal sensitive data in the case of
cryptographic computations. (CVE-2006-1056)

Marcel Holtmann discovered that the sys_add_key() did not check that a
new user key is added to a proper keyring. By attempting to add a key
to a normal user key (which is not a keyring), a local attacker could
exploit this to crash the kernel. (CVE-2006-1522)

Ingo Molnar discovered that the SCTP protocol connection tracking
module in netfilter got stuck in an infinite loop on certain empty
packet chunks. A remote attacker could exploit this to cause the
computer to hang. (CVE-2006-1527)

The SCSI I/O driver did not correctly handle the VM_IO flag for memory
mapped pages used for data transfer. A local user could exploit this
to cause a kernel crash. (CVE-2006-1528)

The choose_new_parent() contained obsolete debugging code. A local
user could exploit this to cause a kernel crash. (CVE-2006-1855)

Kostik Belousov discovered that the readv() and writev() functions did
not query LSM modules for access permission. This could be exploited
to circumvent access restrictions defined by LSM modules such as
SELinux or AppArmor. (CVE-2006-1856)

The SCTP driver did not properly verify certain parameters when
receiving a HB-ACK chunk. By sending a specially crafted packet to an
SCTP socket, a remote attacker could exploit this to trigger a buffer
overflow, which could lead to a crash or possibly even arbitrary code
execution. (CVE-2006-1857)

The sctp_walk_params() function in the SCTP driver incorrectly used
rounded values for bounds checking instead of the precise values. By
sending a specially crafted packet to an SCTP socket, a remote
attacker could exploit this to crash the kernel. (CVE-2006-1858)

Bjoern Steinbrink reported a memory leak in the __setlease() function.
A local attacker could exploit this to exhaust kernel memory and
render the computer unusable (Denial of Service). (CVE-2006-1859)

Daniel Hokka Zakrisson discovered that the lease_init() did not
properly handle locking. A local attacker could exploit this to cause
a kernel deadlock (Denial of Service). (CVE-2006-1860)

Mark Moseley discovered that the CIFS file system driver did not
filter out '..\\' path components. A local attacker could exploit this
to break out of a chroot environment on a mounted SMB share.
(CVE-2006-1863) The same vulnerability applies to the older smb file
system. (CVE-2006-1864)

Hugh Dickins discovered that the mprotect() function allowed an user
to change a read-only shared memory attachment to become writable,
which bypasses IPC (inter-process communication) permissions.
(CVE-2006-2071)

The SCTP (Stream Control Transmission Protocol) driver triggered a
kernel panic on unexpected packets while the session was in the CLOSED
state, instead of silently ignoring the packets. A remote attacker
could exploit this to crash the computer. (CVE-2006-2271)

The SCTP driver did not handle control chunks if they arrived in
fragmented packets. By sending specially crafted packets to an SCTP
socket, a remote attacker could exploit this to crash the target
machine. (CVE-2006-2272)

The SCTP driver did not correctly handle packets containing more than
one DATA fragment. By sending specially crafted packets to an SCTP
socket, a remote attacker could exploit this to crash the target
machine. (CVE-2006-2274)

The SCTP driver did not correcly buffer incoming packets. By sending a
large number of small messages to a receiver application that cannot
process the messages quickly enough, a remote attacker could exploit
this to cause a deadlock in the target machine (Denial of Service).
(CVE-2006-2275)

Patrick McHardy discovered that the snmp_trap_decode() function did
not correctly handle memory allocation in some error conditions. By
sending specially crafted packets to a machine which uses the SNMP
network address translation (NAT), a remote attacker could exploit
this to crash that machine. (CVE-2006-2444)

In addition, the Ubuntu 6.06 LTS update fixes a range of bugs.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware-2.6.15-25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-control");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-ubuntu-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-ubuntu-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-legacy-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-legacy-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-driver-fglrx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-driver-fglrx-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.04|5\.10|6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10 / 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"linux-doc-2.6.10", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-386", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-686", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-686-smp", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-amd64-generic", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-amd64-k8", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-amd64-k8-smp", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-amd64-xeon", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-386", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-686", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-686-smp", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-amd64-generic", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-amd64-k8", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-amd64-k8-smp", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-amd64-xeon", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-patch-ubuntu-2.6.10", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-source-2.6.10", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-tree-2.6.10", pkgver:"2.6.10-34.20")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-doc-2.6.12", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-386", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-686", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-686-smp", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-generic", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-k8", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-k8-smp", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-xeon", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-386", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-686", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-686-smp", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-generic", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-k8", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-k8-smp", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-xeon", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-patch-ubuntu-2.6.12", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-source-2.6.12", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-tree-2.6.12", pkgver:"2.6.12-10.34")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-firmware", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-firmware-2.6.15-25", pkgver:"2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-kernel-source", pkgver:"2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"fglrx-control", pkgver:"2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"fglrx-kernel-source", pkgver:"2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-386", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-686", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-686-smp", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-generic", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-k8", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-k8-smp", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-server", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-xeon", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-doc", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-25", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-25-386", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-25-686", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-25-amd64-generic", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-25-amd64-k8", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-25-amd64-server", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-25-amd64-xeon", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-25-server", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-386", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-686", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-amd64-generic", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-amd64-k8", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-amd64-server", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-amd64-xeon", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-server", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-25-386", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-25-686", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-25-amd64-generic", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-25-amd64-k8", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-25-amd64-server", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-25-amd64-xeon", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-25-server", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-386", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-686", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-amd64-generic", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-amd64-k8", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-amd64-server", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-amd64-xeon", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-server", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-25-386", pkgver:"2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-25-686", pkgver:"2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-25-amd64-generic", pkgver:"2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-25-amd64-k8", pkgver:"2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-25-amd64-xeon", pkgver:"2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-386", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-686", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-amd64-generic", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-amd64-k8", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-amd64-xeon", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-common", pkgver:"2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-server", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source", pkgver:"2.6.15.23")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-25.43")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx", pkgver:"2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-dev", pkgver:"2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-legacy", pkgver:"2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-legacy-dev", pkgver:"2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-kernel-source", pkgver:"1.0.8762+2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-legacy-kernel-source", pkgver:"1.0.7174+2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xorg-driver-fglrx", pkgver:"2.6.15.11-2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xorg-driver-fglrx-dev", pkgver:"2.6.15.11-2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avm-fritz-firmware / avm-fritz-firmware-2.6.15-25 / etc");
}
