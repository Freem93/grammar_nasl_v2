#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2117-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72578);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/26 14:16:25 $");

  script_cve_id("CVE-2013-4563", "CVE-2013-4579", "CVE-2013-4587", "CVE-2013-6367", "CVE-2013-6368", "CVE-2013-6376", "CVE-2013-6382", "CVE-2013-6432", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265", "CVE-2013-7266", "CVE-2013-7267", "CVE-2013-7268", "CVE-2013-7269", "CVE-2013-7270", "CVE-2013-7271", "CVE-2013-7281", "CVE-2014-1438", "CVE-2014-1446");
  script_xref(name:"USN", value:"2117-1");

  script_name(english:"Ubuntu 13.10 : linux vulnerabilities (USN-2117-1)");
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
"Saran Neti reported a flaw in the ipv6 UDP Fragmentation Offload (UFI)
in the Linux kernel. A remote attacker could exploit this flaw to
cause a denial of service (panic). (CVE-2013-4563)

Mathy Vanhoef discovered an error in the the way the ath9k driver was
handling the BSSID masking. A remote attacker could exploit this error
to discover the original MAC address after a spoofing atack.
(CVE-2013-4579)

Andrew Honig reported a flaw in the Linux Kernel's
kvm_vm_ioctl_create_vcpu function of the Kernel Virtual Machine (KVM)
subsystem. A local user could exploit this flaw to gain privileges on
the host machine. (CVE-2013-4587)

Andrew Honig reported a flaw in the apic_get_tmcct function of the
Kernel Virtual Machine (KVM) subsystem if the Linux kernel. A guest OS
user could exploit this flaw to cause a denial of service or host OS
system crash. (CVE-2013-6367)

Andrew Honig reported an error in the Linux Kernel's Kernel Virtual
Machine (KVM) VAPIC synchronization operation. A local user could
exploit this flaw to gain privileges or cause a denial of service
(system crash). (CVE-2013-6368)

Lars Bull discovered a flaw in the recalculate_apic_map function of
the Kernel Virtual Machine (KVM) subsystem in the Linux kernel. A
guest OS user could exploit this flaw to cause a denial of service
(host OS crash). (CVE-2013-6376)

Nico Golde and Fabian Yamaguchi reported buffer underflow errors in
the implementation of the XFS filesystem in the Linux kernel. A local
user with CAP_SYS_ADMIN could exploit these flaw to cause a denial of
service (memory corruption) or possibly other unspecified issues.
(CVE-2013-6382)

A flaw was discovered in the ipv4 ping_recvmsg function of the Linux
kernel. A local user could exploit this flaw to cause a denial of
service (NULL pointer dereference and system crash). (CVE-2013-6432)

mpd reported an information leak in the recvfrom, recvmmsg, and
recvmsg system calls in the Linux kernel. An unprivileged local user
could exploit this flaw to obtain sensitive information from kernel
stack memory. (CVE-2013-7263)

mpb reported an information leak in the Layer Two Tunneling Protocol
(l2tp) of the Linux kernel. A local user could exploit this flaw to
obtain sensitive information from kernel stack memory. (CVE-2013-7264)

mpb reported an information leak in the Phone Network protocol
(phonet) in the Linux kernel. A local user could exploit this flaw to
obtain sensitive information from kernel stack memory. (CVE-2013-7265)

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

mpb reported an information leak in the Low-Rate Wireless Personal
Area Networks support (IEEE 802.15.4) in the Linux kernel. A local
user could exploit this flaw to obtain sensitive information from
kernel stack memory. (CVE-2013-7281)

halfdog reported an error in the AMD K7 and K8 platform support in the
Linux kernel. An unprivileged local user could exploit this flaw on
AMD based systems to cause a denial of service (task kill) or possibly
gain privileges via a crafted application. (CVE-2014-1438)

An information leak was discovered in the Linux kernel's hamradio YAM
driver for AX.25 packet radio. A local user with the CAP_NET_ADMIN
capability could exploit this flaw to obtain sensitive information
from kernel memory. (CVE-2014-1446).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.11-generic and / or
linux-image-3.11-generic-lpae packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.11-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.11-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/19");
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
if (! ereg(pattern:"^(13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"13.10", pkgname:"linux-image-3.11.0-17-generic", pkgver:"3.11.0-17.31")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"linux-image-3.11.0-17-generic-lpae", pkgver:"3.11.0-17.31")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.11-generic / linux-image-3.11-generic-lpae");
}
