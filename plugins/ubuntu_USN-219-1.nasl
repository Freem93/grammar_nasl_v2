#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-219-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65105);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/26 14:16:26 $");

  script_cve_id("CVE-2005-2709", "CVE-2005-2973", "CVE-2005-3055", "CVE-2005-3180", "CVE-2005-3271", "CVE-2005-3272", "CVE-2005-3273", "CVE-2005-3274", "CVE-2005-3275", "CVE-2005-3276");
  script_xref(name:"USN", value:"219-1");

  script_name(english:"Ubuntu 4.10 / 5.10 : linux-source-2.6.8.1/-2.6.10/-2.6.12 vulnerabilities (USN-219-1)");
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
"Al Viro discovered a race condition in the /proc file handler of
network devices. A local attacker could exploit this by opening any
file in /proc/sys/net/ipv4/conf/<interface>/ and waiting until that
interface was shut down. Under certain circumstances this could lead
to a kernel crash or even arbitrary code execution with full kernel
privileges. (CVE-2005-2709)

Tetsuo Handa discovered a local Denial of Service vulnerability in the
udp_v6_get_port() function. On computers which use IPv6, a local
attacker could exploit this to trigger an infinite loop in the kernel.
(CVE-2005-2973)

Harald Welte discovered a Denial of Service vulnerability in the USB
devio driver. A local attacker could exploit this by sending an 'USB
Request Block' (URB) and terminating the sending process before the
arrival of the answer, which left an invalid pointer and caused a
kernel crash. (CVE-2005-3055)

Pavel Roskin discovered an information leak in the Orinoco wireless
card driver. When increasing the buffer length for storing data, the
buffer was not padded with zeros, which exposed a random part of the
system memory to the user. (CVE-2005-3180)

A resource leak has been discovered in the handling of POSIX timers in
the exec() function. This could be exploited to a Denial of Service
attack by a group of local users. This vulnerability only affects
Ubuntu 4.10. (CVE-2005-3271)

Stephen Hemming discovered a weakness in the network bridge driver.
Packets which had already been dropped by the packet filter could
poison the forwarding table, which could be exploited to make the
bridge forward spoofed packages. This vulnerability only affects
Ubuntu 4.10 and 5.04. (CVE-2005-3272)

David S. Miller discovered a buffer overflow in the rose_rt_ioctl()
function. By calling the function with a large 'ngidis' argument, a
local attacker could cause a kernel crash. This vulnerability only
affects Ubuntu 4.10 and 5.04. (CVE-2005-3273)

Neil Horman discovered a race condition in the connection timer
handling. This allowed a local attacker to set up an expiration
handler which modified the connection list while the list still being
traversed, which could result in a kernel crash. This vulnerability
only affects multiprocessor (SMP) systems. (CVE-2005-3274)

Patrick McHardy noticed a logic error in the network address
translation (NAT) connection tracker. A remote attacker could exploit
this by causing two packets for the same protocol to be NATed at the
same time, which resulted in a kernel crash. (CVE-2005-3275)

Paolo Giarrusso discovered an information leak in the
sys_get_thread_area(). The returned structure was not properly
cleared, which exposed a small amount of kernel memory to userspace
programs. This could possibly expose confidential data.
(CVE-2005-3276).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-debian-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-ubuntu-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"linux-doc-2.6.8.1", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-6", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-6-386", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-6-686", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-6-686-smp", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-6-amd64-generic", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-6-amd64-k8", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-6-amd64-k8-smp", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-6-amd64-xeon", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-6-386", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-6-686", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-6-686-smp", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-6-amd64-generic", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-6-amd64-k8", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-6-amd64-k8-smp", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-6-amd64-xeon", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-patch-debian-2.6.8.1", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-source-2.6.8.1", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-tree-2.6.8.1", pkgver:"2.6.8.1-16.25")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-doc-2.6.12", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-386", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-686", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-686-smp", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-generic", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-k8", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-k8-smp", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-xeon", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-386", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-686", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-686-smp", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-generic", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-k8", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-k8-smp", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-xeon", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-patch-ubuntu-2.6.12", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-source-2.6.12", pkgver:"2.6.12-10.24")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-tree-2.6.12", pkgver:"2.6.12-10.24")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.12 / linux-doc-2.6.8.1 / linux-headers-2.6 / etc");
}
