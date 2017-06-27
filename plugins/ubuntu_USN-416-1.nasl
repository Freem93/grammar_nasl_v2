#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-416-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28005);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/10/26 14:26:01 $");

  script_cve_id("CVE-2006-4572", "CVE-2006-4814", "CVE-2006-5749", "CVE-2006-5753", "CVE-2006-5755", "CVE-2006-5757", "CVE-2006-5823", "CVE-2006-6053", "CVE-2006-6054", "CVE-2006-6056", "CVE-2006-6057", "CVE-2006-6106");
  script_bugtraq_id(20920, 20955, 21663, 21883, 22316);
  script_osvdb_id(30298);
  script_xref(name:"USN", value:"416-1");

  script_name(english:"Ubuntu 5.10 / 6.06 LTS / 6.10 : linux-source-2.6.12/2.6.15/2.6.17 vulnerabilities (USN-416-1)");
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
"Mark Dowd discovered that the netfilter iptables module did not
correcly handle fragmented IPv6 packets. By sending specially crafted
packets, a remote attacker could exploit this to bypass firewall
rules. This has has already been fixed for Ubuntu 6.10 in USN-395-1;
this is the corresponding fix for Ubuntu 6.06.(CVE-2006-4572)

Doug Chapman discovered an improper lock handling in the mincore()
function. A local attacker could exploit this to cause an eternal hang
in the kernel, rendering the machine unusable. (CVE-2006-4814)

Al Viro reported that the ISDN PPP module did not initialize the reset
state timer. By sending specially crafted ISDN packets, a remote
attacker could exploit this to crash the kernel. (CVE-2006-5749)

Various syscalls (like listxattr()) misinterpreted the return value of
return_EIO() when encountering bad inodes. By issuing particular
system calls on a malformed file system, a local attacker could
exploit this to crash the kernel. (CVE-2006-5753)

The task switching code did not save and restore EFLAGS of processes.
By starting a specially crafted executable, a local attacker could
exploit this to eventually crash many other running processes. This
only affects the amd64 platform. (CVE-2006-5755)

A race condition was found in the grow_buffers() function. By mounting
a specially crafted ISO9660 or NTFS file system, a local attacker
could exploit this to trigger an infinite loop in the kernel,
rendering the machine unusable. (CVE-2006-5757)

A buffer overread was found in the zlib_inflate() function. By
tricking an user into mounting a specially crafted file system which
uses zlib compression (such as cramfs), this could be exploited to
crash the kernel. (CVE-2006-5823)

The ext3 file system driver did not properly handle corrupted data
structures. By mounting a specially crafted ext3 file system, a local
attacker could exploit this to crash the kernel. (CVE-2006-6053)

The ext2 file system driver did not properly handle corrupted data
structures. By mounting a specially crafted ext2 file system, a local
attacker could exploit this to crash the kernel. (CVE-2006-6054)

The hfs file system driver did not properly handle corrupted data
structures. By mounting a specially crafted hfs file system, a local
attacker could exploit this to crash the kernel. This only affects
systems which enable SELinux (Ubuntu disables SELinux by default).
(CVE-2006-6056)

Several vulnerabilities have been found in the GFS2 file system
driver. Since this driver has never actually worked in Ubuntu 6.10, it
has been disabled. This only affects Ubuntu 6.10. (CVE-2006-6057)

Marcel Holtman discovered several buffer overflows in the Bluetooth
driver. By sending Bluetooth packets with specially crafted CAPI
messages, a remote attacker could exploit these to crash the kernel.
(CVE-2006-6106).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware-2.6.15-28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware-2.6.17-11");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-ubuntu-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-legacy-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-legacy-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vmware-player-kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vmware-player-kernel-modules-2.6.17-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-driver-fglrx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-driver-fglrx-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.10|6\.06|6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.10 / 6.06 / 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.10", pkgname:"linux-doc-2.6.12", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-386", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-686", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-686-smp", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-generic", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-k8", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-k8-smp", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-xeon", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-386", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-686", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-686-smp", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-generic", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-k8", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-k8-smp", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-xeon", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-patch-ubuntu-2.6.12", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-source-2.6.12", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-tree-2.6.12", pkgver:"2.6.12-10.45")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-firmware", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-firmware-2.6.15-28", pkgver:"3.11+2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-kernel-source", pkgver:"3.11+2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"fglrx-control", pkgver:"8.25.18+2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"fglrx-kernel-source", pkgver:"8.25.18+2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-386", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-686", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-686-smp", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-generic", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-k8", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-k8-smp", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-server", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-xeon", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-doc", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-28", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-28-386", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-28-686", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-28-amd64-generic", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-28-amd64-k8", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-28-amd64-server", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-28-amd64-xeon", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-28-server", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-386", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-686", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-amd64-generic", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-amd64-k8", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-amd64-server", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-amd64-xeon", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-server", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-28-386", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-28-686", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-28-amd64-generic", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-28-amd64-k8", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-28-amd64-server", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-28-amd64-xeon", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-28-server", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-386", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-686", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-amd64-generic", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-amd64-k8", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-amd64-server", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-amd64-xeon", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-server", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-28-386", pkgver:"2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-28-686", pkgver:"2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-28-amd64-generic", pkgver:"2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-28-amd64-k8", pkgver:"2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-28-amd64-xeon", pkgver:"2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-386", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-686", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-amd64-generic", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-amd64-k8", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-amd64-xeon", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-server", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source", pkgver:"2.6.15.26")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-28.51")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx", pkgver:"1.0.8776+2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-dev", pkgver:"1.0.8776+2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-legacy", pkgver:"1.0.7174+2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-legacy-dev", pkgver:"1.0.7174+2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-kernel-source", pkgver:"1.0.8776+2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-legacy-kernel-source", pkgver:"1.0.7174+2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xorg-driver-fglrx", pkgver:"7.0.0-8.25.18+2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xorg-driver-fglrx-dev", pkgver:"7.0.0-8.25.18+2.6.15.12-28.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"avm-fritz-firmware", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"avm-fritz-firmware-2.6.17-11", pkgver:"3.11+2.6.17.7-11.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"avm-fritz-kernel-source", pkgver:"3.11+2.6.17.7-11.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"fglrx-control", pkgver:"8.28.8+2.6.17.7-11.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"fglrx-kernel-source", pkgver:"8.28.8+2.6.17.7-11.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-386", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-686", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-686-smp", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-amd64-generic", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-amd64-k8", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-amd64-k8-smp", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-amd64-server", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-amd64-xeon", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-doc", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-doc-2.6.17", pkgver:"2.6.17.1-11.35")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-generic", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-11", pkgver:"2.6.17.1-11.35")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-11-386", pkgver:"2.6.17.1-11.35")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-11-generic", pkgver:"2.6.17.1-11.35")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-11-server", pkgver:"2.6.17.1-11.35")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-386", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-686", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-amd64-generic", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-amd64-k8", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-amd64-server", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-amd64-xeon", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-generic", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-server", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-11-386", pkgver:"2.6.17.1-11.35")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-11-generic", pkgver:"2.6.17.1-11.35")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-11-server", pkgver:"2.6.17.1-11.35")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-386", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-686", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-amd64-generic", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-amd64-k8", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-amd64-server", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-amd64-xeon", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-11-386", pkgver:"2.6.17.1-11.35")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-11-generic", pkgver:"2.6.17.1-11.35")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-11-server", pkgver:"2.6.17.1-11.35")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-generic", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-kdump", pkgver:"2.6.17.1-11.35")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-server", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-kernel-devel", pkgver:"2.6.17.1-11.35")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-libc-dev", pkgver:"2.6.17.1-11.35")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-restricted-modules-2.6.17-11-386", pkgver:"2.6.17.7-11.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-restricted-modules-2.6.17-11-generic", pkgver:"2.6.17.7-11.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-restricted-modules-386", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-restricted-modules-686", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-restricted-modules-amd64-generic", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-restricted-modules-amd64-k8", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-restricted-modules-amd64-xeon", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-restricted-modules-common", pkgver:"2.6.17.7-11.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-restricted-modules-generic", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-server", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-source", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-source-2.6.17", pkgver:"2.6.17.1-11.35")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-glx", pkgver:"1.0.8776+2.6.17.7-11.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-glx-dev", pkgver:"1.0.8776+2.6.17.7-11.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-glx-legacy", pkgver:"1.0.7184+2.6.17.7-11.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-glx-legacy-dev", pkgver:"1.0.7184+2.6.17.7-11.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-kernel-source", pkgver:"1.0.8776+2.6.17.7-11.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-legacy-kernel-source", pkgver:"1.0.7184+2.6.17.7-11.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vmware-player-kernel-modules", pkgver:"2.6.17.11")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vmware-player-kernel-modules-2.6.17-11", pkgver:"2.6.17.7-11.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xorg-driver-fglrx", pkgver:"7.1.0-8.28.8+2.6.17.7-11.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xorg-driver-fglrx-dev", pkgver:"7.1.0-8.28.8+2.6.17.7-11.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avm-fritz-firmware / avm-fritz-firmware-2.6.15-28 / etc");
}
