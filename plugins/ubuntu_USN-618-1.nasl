#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-618-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33255);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2007-4571", "CVE-2007-5904", "CVE-2007-6694", "CVE-2008-0007", "CVE-2008-1294", "CVE-2008-1375", "CVE-2008-1669");
  script_bugtraq_id(25807, 26438, 27686, 29003, 29076);
  script_osvdb_id(39234, 40911);
  script_xref(name:"USN", value:"618-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 : linux-source-2.6.15/20/22 vulnerabilities (USN-618-1)");
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
"It was discovered that the ALSA /proc interface did not write the
correct number of bytes when reporting memory allocations. A local
attacker might be able to access sensitive kernel memory, leading to a
loss of privacy. (CVE-2007-4571)

Multiple buffer overflows were discovered in the handling of CIFS
filesystems. A malicious CIFS server could cause a client system crash
or possibly execute arbitrary code with kernel privileges.
(CVE-2007-5904)

It was discovered that PowerPC kernels did not correctly handle
reporting certain system details. By requesting a specific set of
information, a local attacker could cause a system crash resulting in
a denial of service. (CVE-2007-6694)

It was discovered that some device driver fault handlers did not
correctly verify memory ranges. A local attacker could exploit this to
access sensitive kernel memory, possibly leading to a loss of privacy.
(CVE-2008-0007)

It was discovered that CPU resource limits could be bypassed. A
malicious local user could exploit this to avoid administratively
imposed resource limits. (CVE-2008-1294)

A race condition was discovered between dnotify fcntl() and close() in
the kernel. If a local attacker performed malicious dnotify requests,
they could cause memory consumption leading to a denial of service, or
possibly send arbitrary signals to any process. (CVE-2008-1375)

On SMP systems, a race condition existed in fcntl(). Local attackers
could perform malicious locks, causing system crashes and leading to a
denial of service. (CVE-2008-1669).

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
  script_cwe_id(20, 94, 119, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware-2.6.15-52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware-2.6.20-17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware-2.6.22-15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-control");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-cell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpiacompat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-lowlatency");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-generic");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vmware-player-kernel-modules-2.6.20-17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vmware-server-kernel-modules-2.6.20-17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vmware-tools-kernel-modules-2.6.20-17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-driver-fglrx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-driver-fglrx-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-firmware-2.6.15-52", pkgver:"3.11+2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-kernel-source", pkgver:"3.11+2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"fglrx-control", pkgver:"8.25.18+2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"fglrx-kernel-source", pkgver:"8.25.18+2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-52-386", pkgver:"2.6.15-52.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-52-686", pkgver:"2.6.15-52.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-52-amd64-generic", pkgver:"2.6.15-52.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-52-amd64-k8", pkgver:"2.6.15-52.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-52-amd64-server", pkgver:"2.6.15-52.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-52-amd64-xeon", pkgver:"2.6.15-52.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-backports-modules-2.6.15-52-server", pkgver:"2.6.15-52.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-386", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-686", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-amd64-generic", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-amd64-k8", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-amd64-server", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-amd64-xeon", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-server", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-386", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-686", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-amd64-generic", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-amd64-k8", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-amd64-server", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-amd64-xeon", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-server", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-52-386", pkgver:"2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-52-686", pkgver:"2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-52-amd64-generic", pkgver:"2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-52-amd64-k8", pkgver:"2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-52-amd64-xeon", pkgver:"2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-common", pkgver:"2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-52.67")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx", pkgver:"1.0.8776+2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-dev", pkgver:"1.0.8776+2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-legacy", pkgver:"1.0.7174+2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-legacy-dev", pkgver:"1.0.7174+2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-kernel-source", pkgver:"1.0.8776+2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-legacy-kernel-source", pkgver:"1.0.7174+2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xorg-driver-fglrx", pkgver:"7.0.0-8.25.18+2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xorg-driver-fglrx-dev", pkgver:"7.0.0-8.25.18+2.6.15.12-52.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"avm-fritz-firmware-2.6.20-17", pkgver:"3.11+2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"avm-fritz-kernel-source", pkgver:"3.11+2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"fglrx-control", pkgver:"8.34.8+2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"fglrx-kernel-source", pkgver:"8.34.8+2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-backports-modules-2.6.20-17-386", pkgver:"2.6.20-17.12")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-backports-modules-2.6.20-17-generic", pkgver:"2.6.20-17.12")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-backports-modules-2.6.20-17-server", pkgver:"2.6.20-17.12")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-doc-2.6.20", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-17", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-17-386", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-17-generic", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-17-lowlatency", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-17-server", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-17-386", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-17-generic", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-17-lowlatency", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-17-server", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-17-386", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-17-generic", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-17-lowlatency", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-17-server", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-kernel-devel", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-libc-dev", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-restricted-modules-2.6.20-17-386", pkgver:"2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-restricted-modules-2.6.20-17-generic", pkgver:"2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-restricted-modules-2.6.20-17-lowlatency", pkgver:"2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-restricted-modules-common", pkgver:"2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-source-2.6.20", pkgver:"2.6.20-17.36")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-glx", pkgver:"1.0.9631+2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-glx-dev", pkgver:"1.0.9631+2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-glx-legacy", pkgver:"1.0.7184+2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-glx-legacy-dev", pkgver:"1.0.7184+2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-glx-new", pkgver:"1.0.9755+2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-glx-new-dev", pkgver:"1.0.9755+2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-kernel-source", pkgver:"1.0.9631+2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-legacy-kernel-source", pkgver:"1.0.7184+2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-new-kernel-source", pkgver:"1.0.9755+2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vmware-player-kernel-modules-2.6.20-17", pkgver:"2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vmware-server-kernel-modules-2.6.20-17", pkgver:"2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vmware-tools-kernel-modules-2.6.20-17", pkgver:"2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xorg-driver-fglrx", pkgver:"7.1.0-8.34.8+2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xorg-driver-fglrx-dev", pkgver:"7.1.0-8.34.8+2.6.20.6-17.31")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"avm-fritz-firmware-2.6.22-15", pkgver:"3.11+2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"avm-fritz-kernel-source", pkgver:"3.11+2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"fglrx-control", pkgver:"8.37.6+2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"fglrx-kernel-source", pkgver:"8.37.6+2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-backports-modules-2.6.22-15-386", pkgver:"2.6.22-15.16")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-backports-modules-2.6.22-15-generic", pkgver:"2.6.22-15.16")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-backports-modules-2.6.22-15-rt", pkgver:"2.6.22-15.16")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-backports-modules-2.6.22-15-server", pkgver:"2.6.22-15.16")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-backports-modules-2.6.22-15-ume", pkgver:"2.6.22-15.16")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-backports-modules-2.6.22-15-xen", pkgver:"2.6.22-15.16")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-doc-2.6.22", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-386", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-generic", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-rt", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-server", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-ume", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-virtual", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-xen", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-386", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-cell", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-generic", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-lpia", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-lpiacompat", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-rt", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-server", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-ume", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-virtual", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-xen", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-15-386", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-15-generic", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-15-server", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-15-virtual", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-kernel-devel", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-libc-dev", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-restricted-modules-2.6.22-15-386", pkgver:"2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-restricted-modules-2.6.22-15-generic", pkgver:"2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-restricted-modules-2.6.22-15-rt", pkgver:"2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-restricted-modules-2.6.22-15-xen", pkgver:"2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-restricted-modules-common", pkgver:"2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-source-2.6.22", pkgver:"2.6.22-15.54")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-15-386", pkgver:"2.6.22-15.39")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-15-generic", pkgver:"2.6.22-15.39")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-15-rt", pkgver:"2.6.22-15.39")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-15-server", pkgver:"2.6.22-15.39")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-15-ume", pkgver:"2.6.22-15.39")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-15-virtual", pkgver:"2.6.22-15.39")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-ubuntu-modules-2.6.22-15-xen", pkgver:"2.6.22-15.39")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-glx", pkgver:"1.0.9639+2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-glx-dev", pkgver:"1.0.9639+2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-glx-legacy", pkgver:"1.0.7185+2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-glx-legacy-dev", pkgver:"1.0.7185+2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-glx-new", pkgver:"100.14.19+2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-glx-new-dev", pkgver:"100.14.19+2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-kernel-source", pkgver:"1.0.9639+2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-legacy-kernel-source", pkgver:"1.0.7185+2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"nvidia-new-kernel-source", pkgver:"100.14.19+2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"xorg-driver-fglrx", pkgver:"7.1.0-8.37.6+2.6.22.4-15.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"xorg-driver-fglrx-dev", pkgver:"7.1.0-8.37.6+2.6.22.4-15.11")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avm-fritz-firmware-2.6.15-52 / avm-fritz-firmware-2.6.20-17 / etc");
}
