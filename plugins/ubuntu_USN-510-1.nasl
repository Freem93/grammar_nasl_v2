#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-510-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28114);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/01 21:07:51 $");

  script_cve_id("CVE-2007-2525", "CVE-2007-2875", "CVE-2007-2876", "CVE-2007-2878", "CVE-2007-3104", "CVE-2007-3105", "CVE-2007-3513", "CVE-2007-3642", "CVE-2007-3843", "CVE-2007-3848", "CVE-2007-3851", "CVE-2007-4308");
  script_osvdb_id(37112, 37113, 37115, 37116, 37117, 37122, 37123, 37124, 37288, 37289);
  script_xref(name:"USN", value:"510-1");

  script_name(english:"Ubuntu 7.04 : linux-source-2.6.20 vulnerabilities (USN-510-1)");
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
"A flaw was discovered in the PPP over Ethernet implementation. Local
attackers could manipulate ioctls and cause kernel memory consumption
leading to a denial of service. (CVE-2007-2525)

An integer underflow was discovered in the cpuset filesystem. If
mounted, local attackers could obtain kernel memory using large file
offsets while reading the tasks file. This could disclose sensitive
data. (CVE-2007-2875)

Vilmos Nebehaj discovered that the SCTP netfilter code did not
correctly validate certain states. A remote attacker could send a
specially crafted packet causing a denial of service. (CVE-2007-2876)

Luca Tettamanti discovered a flaw in the VFAT compat ioctls on 64-bit
systems. A local attacker could corrupt a kernel_dirent struct and
cause a denial of service. (CVE-2007-2878)

A flaw in the sysfs_readdir function allowed a local user to cause a
denial of service by dereferencing a NULL pointer. (CVE-2007-3104)

A buffer overflow was discovered in the random number generator. In
environments with granular assignment of root privileges, a local
attacker could gain additional privileges. (CVE-2007-3105)

A flaw was discovered in the usblcd driver. A local attacker could
cause large amounts of kernel memory consumption, leading to a denial
of service. (CVE-2007-3513)

Zhongling Wen discovered that the h323 conntrack handler did not
correctly handle certain bitfields. A remote attacker could send a
specially crafted packet and cause a denial of service.
(CVE-2007-3642)

A flaw was discovered in the CIFS mount security checking. Remote
attackers could spoof CIFS network traffic, which could lead a client
to trust the connection. (CVE-2007-3843)

It was discovered that certain setuid-root processes did not correctly
reset process death signal handlers. A local user could manipulate
this to send signals to processes they would not normally have access
to. (CVE-2007-3848)

The Direct Rendering Manager for the i915 driver could be made to
write to arbitrary memory locations. An attacker with access to a
running X11 session could send a specially crafted buffer and gain
root privileges. (CVE-2007-3851)

It was discovered that the aacraid SCSI driver did not correctly check
permissions on certain ioctls. A local attacker could cause a denial
of service or gain privileges. (CVE-2007-4308).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.20");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/04");
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
if (! ereg(pattern:"^(7\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 7.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"7.04", pkgname:"linux-doc-2.6.20", pkgver:"2.6.20-16.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16", pkgver:"2.6.20-16.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-386", pkgver:"2.6.20-16.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-generic", pkgver:"2.6.20-16.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-lowlatency", pkgver:"2.6.20-16.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-server", pkgver:"2.6.20-16.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-386", pkgver:"2.6.20-16.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-generic", pkgver:"2.6.20-16.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-lowlatency", pkgver:"2.6.20-16.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-server", pkgver:"2.6.20-16.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-386", pkgver:"2.6.20-16.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-generic", pkgver:"2.6.20-16.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-lowlatency", pkgver:"2.6.20-16.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-server", pkgver:"2.6.20-16.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-kernel-devel", pkgver:"2.6.20-16.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-libc-dev", pkgver:"2.6.20-16.31")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-source-2.6.20", pkgver:"2.6.20-16.31")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.20 / linux-headers-2.6 / linux-headers-2.6-386 / etc");
}
