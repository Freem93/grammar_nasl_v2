#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-574-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30183);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2006-6058", "CVE-2007-3107", "CVE-2007-4567", "CVE-2007-4849", "CVE-2007-4997", "CVE-2007-5093", "CVE-2007-5500", "CVE-2007-5501", "CVE-2007-5966", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6417", "CVE-2008-0001");
  script_osvdb_id(40913, 44120, 58753);
  script_xref(name:"USN", value:"574-1");

  script_name(english:"Ubuntu 6.10 / 7.04 / 7.10 : linux-source-2.6.17/20/22 vulnerabilities (USN-574-1)");
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
"The minix filesystem did not properly validate certain filesystem
values. If a local attacker could trick the system into attempting to
mount a corrupted minix filesystem, the kernel could be made to hang
for long periods of time, resulting in a denial of service. This was
only vulnerable in Ubuntu 7.04 and 7.10. (CVE-2006-6058)

The signal handling on PowerPC systems using HTX allowed local users
to cause a denial of service via floating point corruption. This was
only vulnerable in Ubuntu 6.10 and 7.04. (CVE-2007-3107)

The Linux kernel did not properly validate the hop-by-hop IPv6
extended header. Remote attackers could send a crafted IPv6 packet and
cause a denial of service via kernel panic. This was only vulnerable
in Ubuntu 7.04. (CVE-2007-4567)

The JFFS2 filesystem with ACL support enabled did not properly store
permissions during inode creation and ACL setting. Local users could
possibly access restricted files after a remount. This was only
vulnerable in Ubuntu 7.04 and 7.10. (CVE-2007-4849)

Chris Evans discovered an issue with certain drivers that use the
ieee80211_rx function. Remote attackers could send a crafted 802.11
frame and cause a denial of service via crash. This was only
vulnerable in Ubuntu 7.04 and 7.10. (CVE-2007-4997)

Alex Smith discovered an issue with the pwc driver for certain webcam
devices. A local user with physical access to the system could remove
the device while a userspace application had it open and cause the USB
subsystem to block. This was only vulnerable in Ubuntu 7.04.
(CVE-2007-5093)

Scott James Remnant discovered a coding error in ptrace. Local users
could exploit this and cause the kernel to enter an infinite loop.
This was only vulnerable in Ubuntu 7.04 and 7.10. (CVE-2007-5500)

It was discovered that the Linux kernel could dereference a NULL
pointer when processing certain IPv4 TCP packets. A remote attacker
could send a crafted TCP ACK response and cause a denial of service
via crash. This was only vulnerable in Ubuntu 7.10. (CVE-2007-5501)

Warren Togami discovered that the hrtimer subsystem did not properly
check for large relative timeouts. A local user could exploit this and
cause a denial of service via soft lockup. (CVE-2007-5966)

Venustech AD-LAB discovered a buffer overflow in the isdn net
subsystem. This issue is exploitable by local users via crafted input
to the isdn_ioctl function. (CVE-2007-6063)

It was discovered that the isdn subsystem did not properly check for
NULL termination when performing ioctl handling. A local user could
exploit this to cause a denial of service. (CVE-2007-6151)

Blake Frantz discovered that when a root process overwrote an existing
core file, the resulting core file retained the previous core file's
ownership. Local users could exploit this to gain access to sensitive
information. (CVE-2007-6206)

Hugh Dickins discovered the when using the tmpfs filesystem, under
rare circumstances, a kernel page may be improperly cleared. A local
user may be able to exploit this and read sensitive kernel data or
cause a denial of service via crash. (CVE-2007-6417)

Bill Roman discovered that the VFS subsystem did not properly check
access modes. A local user may be able to gain removal privileges on
directories. (CVE-2008-0001).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 119, 189, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.22");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/05");
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
if (! ereg(pattern:"^(6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.10", pkgname:"linux-doc-2.6.17", pkgver:"2.6.17.1-12.43")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12", pkgver:"2.6.17.1-12.43")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12-386", pkgver:"2.6.17.1-12.43")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12-generic", pkgver:"2.6.17.1-12.43")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12-server", pkgver:"2.6.17.1-12.43")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-12-386", pkgver:"2.6.17.1-12.43")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-12-generic", pkgver:"2.6.17.1-12.43")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-12-server", pkgver:"2.6.17.1-12.43")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-12-386", pkgver:"2.6.17.1-12.43")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-12-generic", pkgver:"2.6.17.1-12.43")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-12-server", pkgver:"2.6.17.1-12.43")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-kdump", pkgver:"2.6.17.1-12.43")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-kernel-devel", pkgver:"2.6.17.1-12.43")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-libc-dev", pkgver:"2.6.17.1-12.43")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-source-2.6.17", pkgver:"2.6.17.1-12.43")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-doc-2.6.20", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-386", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-generic", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-lowlatency", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-server", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-386", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-generic", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-lowlatency", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-server", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-386", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-generic", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-lowlatency", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-server", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-kernel-devel", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-libc-dev", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-source-2.6.20", pkgver:"2.6.20-16.34")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-doc-2.6.22", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-386", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-generic", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-rt", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-server", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-ume", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-virtual", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-xen", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-386", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-cell", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-generic", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-lpia", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-lpiacompat", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-rt", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-server", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-ume", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-virtual", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-xen", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-14-386", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-14-generic", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-14-server", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-14-virtual", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-kernel-devel", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-libc-dev", pkgver:"2.6.22-14.51")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-source-2.6.22", pkgver:"2.6.22-14.51")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.17 / linux-doc-2.6.20 / linux-doc-2.6.22 / etc");
}
