#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-751-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37337);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-4307", "CVE-2008-6107", "CVE-2009-0028", "CVE-2009-0031", "CVE-2009-0065", "CVE-2009-0269", "CVE-2009-0322", "CVE-2009-0605", "CVE-2009-0675", "CVE-2009-0676", "CVE-2009-0745", "CVE-2009-0746", "CVE-2009-0747", "CVE-2009-0748", "CVE-2009-0834", "CVE-2009-0835", "CVE-2009-0859", "CVE-2009-1046");
  script_bugtraq_id(33113, 33672, 33846, 33948, 33951, 34020);
  script_osvdb_id(52862, 56163);
  script_xref(name:"USN", value:"751-1");

  script_name(english:"Ubuntu 7.10 / 8.04 LTS / 8.10 : linux, linux-source-2.6.22 vulnerabilities (USN-751-1)");
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
"NFS did not correctly handle races between fcntl and interrupts. A
local attacker on an NFS mount could consume unlimited kernel memory,
leading to a denial of service. Ubuntu 8.10 was not affected.
(CVE-2008-4307)

Sparc syscalls did not correctly check mmap regions. A local attacker
could cause a system panic, leading to a denial of service. Ubuntu
8.10 was not affected. (CVE-2008-6107)

In certain situations, cloned processes were able to send signals to
parent processes, crossing privilege boundaries. A local attacker
could send arbitrary signals to parent processes, leading to a denial
of service. (CVE-2009-0028)

The kernel keyring did not free memory correctly. A local attacker
could consume unlimited kernel memory, leading to a denial of service.
(CVE-2009-0031)

The SCTP stack did not correctly validate FORWARD-TSN packets. A
remote attacker could send specially crafted SCTP traffic causing a
system crash, leading to a denial of service. (CVE-2009-0065)

The eCryptfs filesystem did not correctly handle certain VFS return
codes. A local attacker with write-access to an eCryptfs filesystem
could cause a system crash, leading to a denial of service.
(CVE-2009-0269)

The Dell platform device did not correctly validate user parameters. A
local attacker could perform specially crafted reads to crash the
system, leading to a denial of service. (CVE-2009-0322)

The page fault handler could consume stack memory. A local attacker
could exploit this to crash the system or gain root privileges with a
Kprobe registered. Only Ubuntu 8.10 was affected. (CVE-2009-0605)

Network interfaces statistics for the SysKonnect FDDI driver did not
check capabilities. A local user could reset statistics, potentially
interfering with packet accounting systems. (CVE-2009-0675)

The getsockopt function did not correctly clear certain parameters. A
local attacker could read leaked kernel memory, leading to a loss of
privacy. (CVE-2009-0676)

The ext4 filesystem did not correctly clear group descriptors when
resizing. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2009-0745)

The ext4 filesystem did not correctly validate certain fields. A local
attacker could mount a malicious ext4 filesystem, causing a system
crash, leading to a denial of service. (CVE-2009-0746, CVE-2009-0747,
CVE-2009-0748)

The syscall interface did not correctly validate parameters when
crossing the 64-bit/32-bit boundary. A local attacker could bypass
certain syscall restricts via crafted syscalls. (CVE-2009-0834,
CVE-2009-0835)

The shared memory subsystem did not correctly handle certain shmctl
calls when CONFIG_SHMEM was disabled. Ubuntu kernels were not
vulnerable, since CONFIG_SHMEM is enabled by default. (CVE-2009-0859)

The virtual consoles did not correctly handle certain UTF-8 sequences.
A local attacker on the physical console could exploit this to cause a
system crash, leading to a denial of service. (CVE-2009-1046).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 189, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-cell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpiacompat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.27");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(7\.10|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 7.10 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"7.10", pkgname:"linux-doc-2.6.22", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-386", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-generic", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-rt", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-server", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-ume", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-virtual", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-xen", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-386", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-cell", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-generic", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-lpia", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-lpiacompat", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-rt", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-server", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-ume", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-virtual", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-xen", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-16-386", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-16-generic", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-16-server", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-16-virtual", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-kernel-devel", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-libc-dev", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-source-2.6.22", pkgver:"2.6.22-16.62")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-doc-2.6.24", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-23", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-23-386", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-23-generic", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-23-openvz", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-23-rt", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-23-server", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-23-virtual", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-23-xen", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-386", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-generic", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-lpia", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-lpiacompat", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-openvz", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-rt", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-server", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-virtual", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-xen", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-23-386", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-23-generic", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-23-server", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-23-virtual", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-kernel-devel", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-libc-dev", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-source-2.6.24", pkgver:"2.6.24-23.52")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-doc-2.6.27", pkgver:"2.6.27-11.31")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-11", pkgver:"2.6.27-11.31")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-11-generic", pkgver:"2.6.27-11.31")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-11-server", pkgver:"2.6.27-11.31")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-11-generic", pkgver:"2.6.27-11.31")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-11-server", pkgver:"2.6.27-11.31")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-11-virtual", pkgver:"2.6.27-11.31")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-libc-dev", pkgver:"2.6.27-11.31")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-source-2.6.27", pkgver:"2.6.27-11.31")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.22 / linux-doc-2.6.24 / linux-doc-2.6.27 / etc");
}
