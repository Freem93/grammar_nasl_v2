#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2128-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72857);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/26 14:16:25 $");

  script_cve_id("CVE-2013-0160", "CVE-2013-2929", "CVE-2013-4587", "CVE-2013-6367", "CVE-2013-6380", "CVE-2013-6382", "CVE-2013-7027", "CVE-2013-7266", "CVE-2013-7267", "CVE-2013-7268", "CVE-2013-7269", "CVE-2013-7270", "CVE-2013-7271", "CVE-2014-1444", "CVE-2014-1445", "CVE-2014-1446", "CVE-2014-1874");
  script_bugtraq_id(57176, 63887, 63889, 64013, 64111, 64270, 64328, 64739, 64741, 64742, 64743, 64744, 64746, 64952, 64953, 64954, 65459);
  script_osvdb_id(89143);
  script_xref(name:"USN", value:"2128-1");

  script_name(english:"Ubuntu 10.04 LTS : linux vulnerabilities (USN-2128-1)");
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
"An information leak was discovered in the Linux kernel when inotify is
used to monitor the /dev/ptmx device. A local user could exploit this
flaw to discover keystroke timing and potentially discover sensitive
information like password length. (CVE-2013-0160)

Vasily Kulikov reported a flaw in the Linux kernel's implementation of
ptrace. An unprivileged local user could exploit this flaw to obtain
sensitive information from kernel memory. (CVE-2013-2929)

Andrew Honig reported a flaw in the Linux Kernel's
kvm_vm_ioctl_create_vcpu function of the Kernel Virtual Machine (KVM)
subsystem. A local user could exploit this flaw to gain privileges on
the host machine. (CVE-2013-4587)

Andrew Honig reported a flaw in the apic_get_tmcct function of the
Kernel Virtual Machine (KVM) subsystem if the Linux kernel. A guest OS
user could exploit this flaw to cause a denial of service or host OS
system crash. (CVE-2013-6367)

Nico Golde and Fabian Yamaguchi reported a flaw in the driver for
Adaptec AACRAID scsi raid devices in the Linux kernel. A local user
could use this flaw to cause a denial of service or possibly other
unspecified impact. (CVE-2013-6380)

Nico Golde and Fabian Yamaguchi reported buffer underflow errors in
the implementation of the XFS filesystem in the Linux kernel. A local
user with CAP_SYS_ADMIN could exploit these flaw to cause a denial of
service (memory corruption) or possibly other unspecified issues.
(CVE-2013-6382)

Evan Huus reported a buffer overflow in the Linux kernel's radiotap
header parsing. A remote attacker could cause a denial of service
(buffer over- read) via a specially crafted header. (CVE-2013-7027)

An information leak was discovered in the recvfrom, recvmmsg, and
recvmsg systemcalls when used with ISDN sockets in the Linux kernel. A
local user could exploit this leak to obtain potentially sensitive
information from kernel memory. (CVE-2013-7266)

An information leak was discovered in the recvfrom, recvmmsg, and
recvmsg systemcalls when used with apple talk sockets in the Linux
kernel. A local user could exploit this leak to obtain potentially
sensitive information from kernel memory. (CVE-2013-7267)

An information leak was discovered in the recvfrom, recvmmsg, and
recvmsg systemcalls when used with ipx protocol sockets in the Linux
kernel. A local user could exploit this leak to obtain potentially
sensitive information from kernel memory. (CVE-2013-7268)

An information leak was discovered in the recvfrom, recvmmsg, and
recvmsg systemcalls when used with the netrom address family in the
Linux kernel. A local user could exploit this leak to obtain
potentially sensitive information from kernel memory. (CVE-2013-7269)

An information leak was discovered in the recvfrom, recvmmsg, and
recvmsg systemcalls when used with packet address family sockets in
the Linux kernel. A local user could exploit this leak to obtain
potentially sensitive information from kernel memory. (CVE-2013-7270)

An information leak was discovered in the recvfrom, recvmmsg, and
recvmsg systemcalls when used with x25 protocol sockets in the Linux
kernel. A local user could exploit this leak to obtain potentially
sensitive information from kernel memory. (CVE-2013-7271)

An information leak was discovered in the Linux kernel's SIOCWANDEV
ioctl call. A local user with the CAP_NET_ADMIN capability could
exploit this flaw to obtain potentially sensitive information from
kernel memory. (CVE-2014-1444)

An information leak was discovered in the wanxl ioctl function the the
Linux kernel. A local user could exploit this flaw to obtain
potentially sensitive information from kernel memory. (CVE-2014-1445)

An information leak was discovered in the Linux kernel's hamradio YAM
driver for AX.25 packet radio. A local user with the CAP_NET_ADMIN
capability could exploit this flaw to obtain sensitive information
from kernel memory. (CVE-2014-1446)

Matthew Thode reported a denial of service vulnerability in the Linux
kernel when SELinux support is enabled. A local user with the
CAP_MAC_ADMIN capability (and the SELinux mac_admin permission if
running in enforcing mode) could exploit this flaw to cause a denial
of service (kernel crash). (CVE-2014-1874).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/06");
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
if (! ereg(pattern:"^(10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-57-386", pkgver:"2.6.32-57.119")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-57-generic", pkgver:"2.6.32-57.119")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-57-generic-pae", pkgver:"2.6.32-57.119")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-57-lpia", pkgver:"2.6.32-57.119")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-57-preempt", pkgver:"2.6.32-57.119")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-57-server", pkgver:"2.6.32-57.119")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-57-versatile", pkgver:"2.6.32-57.119")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-57-virtual", pkgver:"2.6.32-57.119")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-2.6-386 / linux-image-2.6-generic / etc");
}
