#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-679-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37683);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2007-5498", "CVE-2008-3831", "CVE-2008-4210", "CVE-2008-4554", "CVE-2008-4576", "CVE-2008-4618", "CVE-2008-4933", "CVE-2008-4934", "CVE-2008-5025", "CVE-2008-5029", "CVE-2008-5033");
  script_bugtraq_id(31368, 31634, 31792, 31903, 32093, 32094, 32154, 32289);
  script_xref(name:"USN", value:"679-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : linux, linux-source-2.6.15/22 vulnerabilities (USN-679-1)");
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
"It was discovered that the Xen hypervisor block driver did not
correctly validate requests. A user with root privileges in a guest OS
could make a malicious IO request with a large number of blocks that
would crash the host OS, leading to a denial of service. This only
affected Ubuntu 7.10. (CVE-2007-5498)

It was discovered the the i915 video driver did not correctly validate
memory addresses. A local attacker could exploit this to remap memory
that could cause a system crash, leading to a denial of service. This
issue did not affect Ubuntu 6.06 and was previous fixed for Ubuntu
7.10 and 8.04 in USN-659-1. Ubuntu 8.10 has now been corrected as
well. (CVE-2008-3831)

David Watson discovered that the kernel did not correctly strip
permissions when creating files in setgid directories. A local user
could exploit this to gain additional group privileges. This issue
only affected Ubuntu 6.06. (CVE-2008-4210)

Olaf Kirch and Miklos Szeredi discovered that the Linux kernel did not
correctly reject the 'append' flag when handling file splice requests.
A local attacker could bypass append mode and make changes to
arbitrary locations in a file. This issue only affected Ubuntu 7.10
and 8.04. (CVE-2008-4554)

It was discovered that the SCTP stack did not correctly handle
INIT-ACK. A remote user could exploit this by sending specially
crafted SCTP traffic which would trigger a crash in the system,
leading to a denial of service. This issue did not affect Ubuntu 8.10.
(CVE-2008-4576)

It was discovered that the SCTP stack did not correctly handle bad
packet lengths. A remote user could exploit this by sending specially
crafted SCTP traffic which would trigger a crash in the system,
leading to a denial of service. This issue did not affect Ubuntu 8.10.
(CVE-2008-4618)

Eric Sesterhenn discovered multiple flaws in the HFS+ filesystem. If a
local user or automated system were tricked into mounting a malicious
HFS+ filesystem, the system could crash, leading to a denial of
service. (CVE-2008-4933, CVE-2008-4934, CVE-2008-5025)

It was discovered that the Unix Socket handler did not correctly
process the SCM_RIGHTS message. A local attacker could make a
malicious socket request that would crash the system, leading to a
denial of service. (CVE-2008-5029)

It was discovered that the driver for simple i2c audio interfaces did
not correctly validate certain function pointers. A local user could
exploit this to gain root privileges or crash the system, leading to a
denial of service. (CVE-2008-5033).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware-2.6.15-53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware-2.6.22-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware-2.6.24-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-amdcccle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-control");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lbm-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lbm-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lbm-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lbm-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lbm-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lbm-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lbm-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lum-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lum-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lum-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lum-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lum-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lum-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lum-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-legacy-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-new");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-new-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-legacy-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-new-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-driver-fglrx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-driver-fglrx-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.10|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.10 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-firmware-2.6.15-53", pkgver:"3.11+2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-kernel-source", pkgver:"3.11+2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"fglrx-control", pkgver:"8.25.18+2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"fglrx-kernel-source", pkgver:"8.25.18+2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-53-386", pkgver:"2.6.15-53.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-53-686", pkgver:"2.6.15-53.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-53-amd64-generic", pkgver:"2.6.15-53.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-53-amd64-k8", pkgver:"2.6.15-53.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-53-amd64-server", pkgver:"2.6.15-53.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-53-amd64-xeon", pkgver:"2.6.15-53.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-53-server", pkgver:"2.6.15-53.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-53", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-53-386", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-53-686", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-53-amd64-generic", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-53-amd64-k8", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-53-amd64-server", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-53-amd64-xeon", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-53-server", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-53-386", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-53-686", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-53-amd64-generic", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-53-amd64-k8", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-53-amd64-server", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-53-amd64-xeon", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-53-server", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-53-386", pkgver:"2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-53-686", pkgver:"2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-53-amd64-generic", pkgver:"2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-53-amd64-k8", pkgver:"2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-53-amd64-xeon", pkgver:"2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-common", pkgver:"2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-53.74")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx", pkgver:"1.0.8776+2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-dev", pkgver:"1.0.8776+2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-legacy", pkgver:"1.0.7174+2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-legacy-dev", pkgver:"1.0.7174+2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-kernel-source", pkgver:"1.0.8776+2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-legacy-kernel-source", pkgver:"1.0.7174+2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xorg-driver-fglrx", pkgver:"7.0.0-8.25.18+2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xorg-driver-fglrx-dev", pkgver:"7.0.0-8.25.18+2.6.15.12-53.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"avm-fritz-firmware-2.6.22-16", pkgver:"3.11+2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"avm-fritz-kernel-source", pkgver:"3.11+2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"fglrx-control", pkgver:"8.37.6+2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"fglrx-kernel-source", pkgver:"8.37.6+2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-backports-modules-2.6.22-16-386", pkgver:"2.6.22-16.17")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-backports-modules-2.6.22-16-generic", pkgver:"2.6.22-16.17")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-backports-modules-2.6.22-16-rt", pkgver:"2.6.22-16.17")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-backports-modules-2.6.22-16-server", pkgver:"2.6.22-16.17")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-backports-modules-2.6.22-16-ume", pkgver:"2.6.22-16.17")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-backports-modules-2.6.22-16-xen", pkgver:"2.6.22-16.17")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-doc-2.6.22", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-386", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-generic", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-rt", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-server", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-ume", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-virtual", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-xen", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-386", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-cell", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-generic", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-lpia", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-lpiacompat", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-rt", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-server", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-ume", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-virtual", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-xen", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-16-386", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-16-generic", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-16-server", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-16-virtual", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-kernel-devel", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-libc-dev", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-restricted-modules-2.6.22-16-386", pkgver:"2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-restricted-modules-2.6.22-16-generic", pkgver:"2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-restricted-modules-2.6.22-16-rt", pkgver:"2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-restricted-modules-2.6.22-16-xen", pkgver:"2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-restricted-modules-common", pkgver:"2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-source-2.6.22", pkgver:"2.6.22-16.60")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-16-386", pkgver:"2.6.22-16.41")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-16-generic", pkgver:"2.6.22-16.41")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-16-rt", pkgver:"2.6.22-16.41")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-16-server", pkgver:"2.6.22-16.41")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-16-ume", pkgver:"2.6.22-16.41")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-16-virtual", pkgver:"2.6.22-16.41")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-16-xen", pkgver:"2.6.22-16.41")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-glx", pkgver:"1.0.9639+2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-glx-dev", pkgver:"1.0.9639+2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-glx-legacy", pkgver:"1.0.7185+2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-glx-legacy-dev", pkgver:"1.0.7185+2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-glx-new", pkgver:"100.14.19+2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-glx-new-dev", pkgver:"100.14.19+2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-kernel-source", pkgver:"1.0.9639+2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-legacy-kernel-source", pkgver:"1.0.7185+2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-new-kernel-source", pkgver:"100.14.19+2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"xorg-driver-fglrx", pkgver:"7.1.0-8.37.6+2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"xorg-driver-fglrx-dev", pkgver:"7.1.0-8.37.6+2.6.22.4-16.12")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"avm-fritz-firmware-2.6.24-22", pkgver:"3.11+2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"avm-fritz-kernel-source", pkgver:"3.11+2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"fglrx-amdcccle", pkgver:"2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"fglrx-control", pkgver:"8-3+2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"fglrx-kernel-source", pkgver:"8-3+2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-backports-modules-2.6.24-22-386", pkgver:"2.6.24-22.29")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-backports-modules-2.6.24-22-generic", pkgver:"2.6.24-22.29")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-backports-modules-2.6.24-22-openvz", pkgver:"2.6.24-22.29")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-backports-modules-2.6.24-22-rt", pkgver:"2.6.24-22.29")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-backports-modules-2.6.24-22-server", pkgver:"2.6.24-22.29")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-backports-modules-2.6.24-22-virtual", pkgver:"2.6.24-22.29")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-backports-modules-2.6.24-22-xen", pkgver:"2.6.24-22.29")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-doc-2.6.24", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-22", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-22-386", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-22-generic", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-22-openvz", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-22-rt", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-22-server", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-22-virtual", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-22-xen", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lbm-2.6.24-22-386", pkgver:"2.6.24-22.29")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lbm-2.6.24-22-generic", pkgver:"2.6.24-22.29")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lbm-2.6.24-22-openvz", pkgver:"2.6.24-22.29")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lbm-2.6.24-22-rt", pkgver:"2.6.24-22.29")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lbm-2.6.24-22-server", pkgver:"2.6.24-22.29")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lbm-2.6.24-22-virtual", pkgver:"2.6.24-22.29")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lbm-2.6.24-22-xen", pkgver:"2.6.24-22.29")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-22-386", pkgver:"2.6.24-22.35")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-22-generic", pkgver:"2.6.24-22.35")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-22-openvz", pkgver:"2.6.24-22.35")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-22-rt", pkgver:"2.6.24-22.35")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-22-server", pkgver:"2.6.24-22.35")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-22-virtual", pkgver:"2.6.24-22.35")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-22-xen", pkgver:"2.6.24-22.35")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-22-386", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-22-generic", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-22-lpia", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-22-lpiacompat", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-22-openvz", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-22-rt", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-22-server", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-22-virtual", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-22-xen", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-22-386", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-22-generic", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-22-server", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-22-virtual", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-kernel-devel", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-libc-dev", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-restricted-modules-2.6.24-22-386", pkgver:"2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-restricted-modules-2.6.24-22-generic", pkgver:"2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-restricted-modules-2.6.24-22-openvz", pkgver:"2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-restricted-modules-2.6.24-22-rt", pkgver:"2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-restricted-modules-2.6.24-22-server", pkgver:"2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-restricted-modules-2.6.24-22-xen", pkgver:"2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-restricted-modules-common", pkgver:"2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-source-2.6.24", pkgver:"2.6.24-22.45")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-22-386", pkgver:"2.6.24-22.35")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-22-generic", pkgver:"2.6.24-22.35")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-22-openvz", pkgver:"2.6.24-22.35")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-22-rt", pkgver:"2.6.24-22.35")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-22-server", pkgver:"2.6.24-22.35")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-22-virtual", pkgver:"2.6.24-22.35")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-22-xen", pkgver:"2.6.24-22.35")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-glx", pkgver:"96.43.05+2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-glx-dev", pkgver:"96.43.05+2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-glx-legacy", pkgver:"71.86.04+2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-glx-legacy-dev", pkgver:"71.86.04+2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-glx-new", pkgver:"169.12+2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-glx-new-dev", pkgver:"169.12+2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-kernel-source", pkgver:"96.43.05+2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-legacy-kernel-source", pkgver:"71.86.04+2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-new-kernel-source", pkgver:"169.12+2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xorg-driver-fglrx", pkgver:"7.1.0-8-3+2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xorg-driver-fglrx-dev", pkgver:"7.1.0-8-3+2.6.24.14-22.53")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-backports-modules-2.6.27-9-generic", pkgver:"2.6.27-9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-backports-modules-2.6.27-9-server", pkgver:"2.6.27-9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-doc-2.6.27", pkgver:"2.6.27-9.19")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-9", pkgver:"2.6.27-9.19")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-9-generic", pkgver:"2.6.27-9.19")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-9-server", pkgver:"2.6.27-9.19")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-lbm-2.6.27-9-generic", pkgver:"2.6.27-9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-lbm-2.6.27-9-server", pkgver:"2.6.27-9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-9-generic", pkgver:"2.6.27-9.19")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-9-server", pkgver:"2.6.27-9.19")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-9-virtual", pkgver:"2.6.27-9.19")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-libc-dev", pkgver:"2.6.27-9.19")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-restricted-modules-2.6.27-9-generic", pkgver:"2.6.27-9.13")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-restricted-modules-2.6.27-9-server", pkgver:"2.6.27-9.13")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-restricted-modules-common", pkgver:"2.6.27-9.13")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-source-2.6.27", pkgver:"2.6.27-9.19")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avm-fritz-firmware-2.6.15-53 / avm-fritz-firmware-2.6.22-16 / etc");
}
