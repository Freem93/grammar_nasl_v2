#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-947-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46811);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/01 21:21:53 $");

  script_cve_id("CVE-2009-4271", "CVE-2009-4537", "CVE-2010-0008", "CVE-2010-0298", "CVE-2010-0306", "CVE-2010-0419", "CVE-2010-0437", "CVE-2010-0727", "CVE-2010-0741", "CVE-2010-1083", "CVE-2010-1084", "CVE-2010-1085", "CVE-2010-1086", "CVE-2010-1087", "CVE-2010-1088", "CVE-2010-1146", "CVE-2010-1148", "CVE-2010-1162", "CVE-2010-1187", "CVE-2010-1188", "CVE-2010-1488");
  script_xref(name:"USN", value:"947-2");

  script_name(english:"Ubuntu 10.04 LTS : linux regression (USN-947-2)");
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
"USN-947-1 fixed vulnerabilities in the Linux kernel. Fixes for
CVE-2010-0419 caused failures when using KVM in certain situations.
This update reverts that fix until a better solution can be found.

We apologize for the inconvenience.

It was discovered that the Linux kernel did not correctly handle
memory protection of the Virtual Dynamic Shared Object page when
running a 32-bit application on a 64-bit kernel. A local attacker
could exploit this to cause a denial of service. (Only affected Ubuntu
6.06 LTS.) (CVE-2009-4271)

It was discovered that the r8169 network driver did not
correctly check the size of Ethernet frames. A remote
attacker could send specially crafted traffic to crash the
system, leading to a denial of service. (CVE-2009-4537)

Wei Yongjun discovered that SCTP did not correctly validate
certain chunks. A remote attacker could send specially
crafted traffic to monopolize CPU resources, leading to a
denial of service. (Only affected Ubuntu 6.06 LTS.)
(CVE-2010-0008)

It was discovered that KVM did not correctly limit certain
privileged IO accesses on x86. Processes in the guest OS
with access to IO regions could gain further privileges
within the guest OS. (Did not affect Ubuntu 6.06 LTS.)
(CVE-2010-0298, CVE-2010-0306, CVE-2010-0419)

Evgeniy Polyakov discovered that IPv6 did not correctly
handle certain TUN packets. A remote attacker could exploit
this to crash the system, leading to a denial of service.
(Only affected Ubuntu 8.04 LTS.) (CVE-2010-0437)

Sachin Prabhu discovered that GFS2 did not correctly handle
certain locks. A local attacker with write access to a GFS2
filesystem could exploit this to crash the system, leading
to a denial of service. (CVE-2010-0727)

Jamie Strandboge discovered that network virtio in KVM did
not correctly handle certain high-traffic conditions. A
remote attacker could exploit this by sending specially
crafted traffic to a guest OS, causing the guest to crash,
leading to a denial of service. (Only affected Ubuntu 8.04
LTS.) (CVE-2010-0741)

Marcus Meissner discovered that the USB subsystem did not
correctly handle certain error conditions. A local attacker
with access to a USB device could exploit this to read
recently used kernel memory, leading to a loss of privacy
and potentially root privilege escalation. (CVE-2010-1083)

Neil Brown discovered that the Bluetooth subsystem did not
correctly handle large amounts of traffic. A physically
proximate remote attacker could exploit this by sending
specially crafted traffic that would consume all available
system memory, leading to a denial of service. (Ubuntu 6.06
LTS and 10.04 LTS were not affected.) (CVE-2010-1084)

Jody Bruchon discovered that the sound driver for the
AMD780V did not correctly handle certain conditions. A local
attacker with access to this hardward could exploit the flaw
to cause a system crash, leading to a denial of service.
(CVE-2010-1085)

Ang Way Chuang discovered that the DVB driver did not
correctly handle certain MPEG2-TS frames. An attacker could
exploit this by delivering specially crafted frames to
monopolize CPU resources, leading to a denial of service.
(Ubuntu 10.04 LTS was not affected.) (CVE-2010-1086)

Trond Myklebust discovered that NFS did not correctly handle
truncation under certain conditions. A local attacker with
write access to an NFS share could exploit this to crash the
system, leading to a denial of service. (Ubuntu 10.04 LTS
was not affected.) (CVE-2010-1087)

Al Viro discovered that automount of NFS did not correctly
handle symlinks under certain conditions. A local attacker
could exploit this to crash the system, leading to a denial
of service. (Ubuntu 6.06 LTS and Ubuntu 10.04 LTS were not
affected.) (CVE-2010-1088)

Matt McCutchen discovered that ReiserFS did not correctly
protect xattr files in the .reiserfs_priv directory. A local
attacker could exploit this to gain root privileges or crash
the system, leading to a denial of service. (CVE-2010-1146)

Eugene Teo discovered that CIFS did not correctly validate
arguments when creating new files. A local attacker could
exploit this to crash the system, leading to a denial of
service, or possibly gain root privileges if mmap_min_addr
was not set. (CVE-2010-1148)

Catalin Marinas and Tetsuo Handa discovered that the TTY
layer did not correctly release process IDs. A local
attacker could exploit this to consume kernel resources,
leading to a denial of service. (CVE-2010-1162)

Neil Horman discovered that TIPC did not correctly check its
internal state. A local attacker could send specially
crafted packets via AF_TIPC that would cause the system to
crash, leading to a denial of service. (Ubuntu 6.06 LTS was
not affected.) (CVE-2010-1187)

Masayuki Nakagawa discovered that IPv6 did not correctly
handle certain settings when listening. If a socket were
listening with the IPV6_RECVPKTINFO flag, a remote attacker
could send specially crafted traffic that would cause the
system to crash, leading to a denial of service. (Only
Ubuntu 6.06 LTS was affected.) (CVE-2010-1188)

Oleg Nesterov discovered that the Out-Of-Memory handler did
not correctly handle certain arrangements of processes. A
local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2010-1488).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"10.04", pkgname:"linux-doc", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-22", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-22-386", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-22-generic", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-22-generic-pae", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-22-preempt", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-22-server", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-22-386", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-22-generic", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-22-generic-pae", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-22-lpia", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-22-preempt", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-22-server", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-22-virtual", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-libc-dev", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-source-2.6.32", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-tools-2.6.32-22", pkgver:"2.6.32-22.36")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-tools-common", pkgver:"2.6.32-22.36")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc / linux-headers-2.6 / linux-headers-2.6-386 / etc");
}
