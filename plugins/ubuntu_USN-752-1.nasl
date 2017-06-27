#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-752-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36418);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-4307", "CVE-2008-6107", "CVE-2009-0028", "CVE-2009-0029", "CVE-2009-0065", "CVE-2009-0322", "CVE-2009-0675", "CVE-2009-0676", "CVE-2009-0834", "CVE-2009-0835", "CVE-2009-0859");
  script_bugtraq_id(33113, 33846, 33948, 33951, 34020);
  script_xref(name:"USN", value:"752-1");

  script_name(english:"Ubuntu 6.06 LTS : linux-source-2.6.15 vulnerabilities (USN-752-1)");
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
leading to a denial of service. (CVE-2008-4307)

Sparc syscalls did not correctly check mmap regions. A local attacker
could cause a system panic, leading to a denial of service.
(CVE-2008-6107)

In certain situations, cloned processes were able to send signals to
parent processes, crossing privilege boundaries. A local attacker
could send arbitrary signals to parent processes, leading to a denial
of service. (CVE-2009-0028)

The 64-bit syscall interfaces did not correctly handle sign extension.
A local attacker could make malicious syscalls, possibly gaining root
privileges. The x86_64 architecture was not affected. (CVE-2009-0029)

The SCTP stack did not correctly validate FORWARD-TSN packets. A
remote attacker could send specially crafted SCTP traffic causing a
system crash, leading to a denial of service. (CVE-2009-0065)

The Dell platform device did not correctly validate user parameters. A
local attacker could perform specially crafted reads to crash the
system, leading to a denial of service. (CVE-2009-0322)

Network interfaces statistics for the SysKonnect FDDI driver did not
check capabilities. A local user could reset statistics, potentially
interfering with packet accounting systems. (CVE-2009-0675)

The getsockopt function did not correctly clear certain parameters. A
local attacker could read leaked kernel memory, leading to a loss of
privacy. (CVE-2009-0676)

The syscall interface did not correctly validate parameters when
crossing the 64-bit/32-bit boundary. A local attacker could bypass
certain syscall restricts via crafted syscalls. (CVE-2009-0834,
CVE-2009-0835)

The shared memory subsystem did not correctly handle certain shmctl
calls when CONFIG_SHMEM was disabled. Ubuntu kernels were not
vulnerable, since CONFIG_SHMEM is enabled by default. (CVE-2009-0859).

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware-2.6.15-54");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-legacy-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-legacy-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-driver-fglrx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-driver-fglrx-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/07");
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
if (! ereg(pattern:"^(6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-firmware", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-firmware-2.6.15-54", pkgver:"3.11+2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-kernel-source", pkgver:"3.11+2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"fglrx-control", pkgver:"8.25.18+2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"fglrx-kernel-source", pkgver:"8.25.18+2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-386", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-686", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-686-smp", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-generic", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-k8", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-k8-smp", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-server", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-amd64-xeon", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-54-386", pkgver:"2.6.15-54.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-54-686", pkgver:"2.6.15-54.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-54-amd64-generic", pkgver:"2.6.15-54.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-54-amd64-k8", pkgver:"2.6.15-54.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-54-amd64-server", pkgver:"2.6.15-54.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-54-amd64-xeon", pkgver:"2.6.15-54.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-54-server", pkgver:"2.6.15-54.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-386", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-686", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-amd64-generic", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-amd64-k8", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-amd64-server", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-amd64-xeon", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-server", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-doc", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-386", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-686", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-amd64-generic", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-amd64-k8", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-amd64-server", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-amd64-xeon", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-server", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-386", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-686", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-amd64-generic", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-amd64-k8", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-amd64-server", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-amd64-xeon", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-server", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-386", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-686", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-amd64-generic", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-amd64-k8", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-amd64-server", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-amd64-xeon", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-server", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-386", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-686", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-amd64-generic", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-amd64-k8", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-amd64-server", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-amd64-xeon", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-server", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-54-386", pkgver:"2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-54-686", pkgver:"2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-54-amd64-generic", pkgver:"2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-54-amd64-k8", pkgver:"2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-54-amd64-xeon", pkgver:"2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-386", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-686", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-amd64-generic", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-amd64-k8", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-amd64-xeon", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-common", pkgver:"2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-server", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source", pkgver:"2.6.15.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-54.76")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx", pkgver:"1.0.8776+2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-dev", pkgver:"1.0.8776+2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-legacy", pkgver:"1.0.7174+2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-legacy-dev", pkgver:"1.0.7174+2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-kernel-source", pkgver:"1.0.8776+2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-legacy-kernel-source", pkgver:"1.0.7174+2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xorg-driver-fglrx", pkgver:"7.0.0-8.25.18+2.6.15.12-54.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xorg-driver-fglrx-dev", pkgver:"7.0.0-8.25.18+2.6.15.12-54.5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avm-fritz-firmware / avm-fritz-firmware-2.6.15-54 / etc");
}
