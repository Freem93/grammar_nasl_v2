#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-614-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33093);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2007-6694", "CVE-2008-1375", "CVE-2008-1669", "CVE-2008-1675");
  script_xref(name:"USN", value:"614-1");

  script_name(english:"Ubuntu 8.04 LTS : linux vulnerabilities (USN-614-1)");
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
"It was discovered that PowerPC kernels did not correctly handle
reporting certain system details. By requesting a specific set of
information, a local attacker could cause a system crash resulting in
a denial of service. (CVE-2007-6694)

A race condition was discovered between dnotify fcntl() and close() in
the kernel. If a local attacker performed malicious dnotify requests,
they could cause memory consumption leading to a denial of service, or
possibly send arbitrary signals to any process. (CVE-2008-1375)

On SMP systems, a race condition existed in fcntl(). Local attackers
could perform malicious locks, causing system crashes and leading to a
denial of service. (CVE-2008-1669)

The tehuti network driver did not correctly handle certain IO
functions. A local attacker could perform malicious requests to the
driver, potentially accessing kernel memory, leading to privilege
escalation or access to private system information. (CVE-2008-1675).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(94, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware-2.6.24-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-amdcccle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-control");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-backports-modules-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpiacompat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ubuntu-modules-2.6-server");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/04");
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
if (! ereg(pattern:"^(8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"avm-fritz-firmware-2.6.24-18", pkgver:"3.11+2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"avm-fritz-kernel-source", pkgver:"3.11+2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"fglrx-amdcccle", pkgver:"2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"fglrx-control", pkgver:"8-3+2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"fglrx-kernel-source", pkgver:"8-3+2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-backports-modules-2.6.24-18-386", pkgver:"2.6.24-18.16")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-backports-modules-2.6.24-18-generic", pkgver:"2.6.24-18.16")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-backports-modules-2.6.24-18-openvz", pkgver:"2.6.24-18.16")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-backports-modules-2.6.24-18-rt", pkgver:"2.6.24-18.16")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-backports-modules-2.6.24-18-server", pkgver:"2.6.24-18.16")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-backports-modules-2.6.24-18-virtual", pkgver:"2.6.24-18.16")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-backports-modules-2.6.24-18-xen", pkgver:"2.6.24-18.16")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-doc-2.6.24", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-18", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-18-386", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-18-generic", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-18-openvz", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-18-rt", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-18-server", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-18-virtual", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-18-xen", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lbm-2.6.24-18-386", pkgver:"2.6.24-18.16")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lbm-2.6.24-18-generic", pkgver:"2.6.24-18.16")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lbm-2.6.24-18-openvz", pkgver:"2.6.24-18.16")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lbm-2.6.24-18-rt", pkgver:"2.6.24-18.16")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lbm-2.6.24-18-server", pkgver:"2.6.24-18.16")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lbm-2.6.24-18-virtual", pkgver:"2.6.24-18.16")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lbm-2.6.24-18-xen", pkgver:"2.6.24-18.16")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-18-386", pkgver:"2.6.24-18.26")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-18-generic", pkgver:"2.6.24-18.26")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-18-openvz", pkgver:"2.6.24-18.26")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-18-rt", pkgver:"2.6.24-18.26")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-18-server", pkgver:"2.6.24-18.26")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-18-virtual", pkgver:"2.6.24-18.26")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-lum-2.6.24-18-xen", pkgver:"2.6.24-18.26")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-18-386", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-18-generic", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-18-lpia", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-18-lpiacompat", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-18-openvz", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-18-rt", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-18-server", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-18-virtual", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-18-xen", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-18-386", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-18-generic", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-18-server", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-18-virtual", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-kernel-devel", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-libc-dev", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-restricted-modules-2.6.24-18-386", pkgver:"2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-restricted-modules-2.6.24-18-generic", pkgver:"2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-restricted-modules-2.6.24-18-openvz", pkgver:"2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-restricted-modules-2.6.24-18-rt", pkgver:"2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-restricted-modules-2.6.24-18-server", pkgver:"2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-restricted-modules-2.6.24-18-xen", pkgver:"2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-restricted-modules-common", pkgver:"2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-source-2.6.24", pkgver:"2.6.24-18.32")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-18-386", pkgver:"2.6.24-18.26")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-18-generic", pkgver:"2.6.24-18.26")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-18-openvz", pkgver:"2.6.24-18.26")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-18-rt", pkgver:"2.6.24-18.26")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-18-server", pkgver:"2.6.24-18.26")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-18-virtual", pkgver:"2.6.24-18.26")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-ubuntu-modules-2.6.24-18-xen", pkgver:"2.6.24-18.26")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-glx", pkgver:"96.43.05+2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-glx-dev", pkgver:"96.43.05+2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-glx-legacy", pkgver:"71.86.04+2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-glx-legacy-dev", pkgver:"71.86.04+2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-glx-new", pkgver:"169.12+2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-glx-new-dev", pkgver:"169.12+2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-kernel-source", pkgver:"96.43.05+2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-legacy-kernel-source", pkgver:"71.86.04+2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"nvidia-new-kernel-source", pkgver:"169.12+2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xorg-driver-fglrx", pkgver:"7.1.0-8-3+2.6.24.13-18.41")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xorg-driver-fglrx-dev", pkgver:"7.1.0-8-3+2.6.24.13-18.41")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avm-fritz-firmware-2.6.24-18 / avm-fritz-kernel-source / etc");
}
