#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-558-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29740);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2006-6058", "CVE-2007-4133", "CVE-2007-4567", "CVE-2007-4849", "CVE-2007-4997", "CVE-2007-5093", "CVE-2007-5500", "CVE-2007-5501");
  script_osvdb_id(30506, 39233, 39236, 39239, 39245, 39246, 40564);
  script_xref(name:"USN", value:"558-1");

  script_name(english:"Ubuntu 6.10 / 7.04 / 7.10 : linux-source-2.6.17/20/22 vulnerabilities (USN-558-1)");
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
for long periods of time, resulting in a denial of service.
(CVE-2006-6058)

Certain calculations in the hugetlb code were not correct. A local
attacker could exploit this to cause a kernel panic, leading to a
denial of service. (CVE-2007-4133)

Eric Sesterhenn and Victor Julien discovered that the hop-by-hop IPv6
extended header was not correctly validated. If a system was
configured for IPv6, a remote attacker could send a specially crafted
IPv6 packet and cause the kernel to panic, leading to a denial of
service. This was only vulnerable in Ubuntu 7.04. (CVE-2007-4567)

Permissions were not correctly stored on JFFS2 ACLs. For systems using
ACLs on JFFS2, a local attacker may gain access to private files.
(CVE-2007-4849)

Chris Evans discovered that the 802.11 network stack did not correctly
handle certain QOS frames. A remote attacker on the local wireless
network could send specially crafted packets that would panic the
kernel, resulting in a denial of service. (CVE-2007-4997)

The Philips USB Webcam driver did not correctly handle disconnects. If
a local attacker tricked another user into disconnecting a webcam
unsafely, the kernel could hang or consume CPU resources, leading to a
denial of service. (CVE-2007-5093)

Scott James Remnant discovered that the waitid function could be made
to hang the system. A local attacker could execute a specially crafted
program which would leave the system unresponsive, resulting in a
denial of service. (CVE-2007-5500)

Ilpo Jarvinen discovered that it might be possible for the TCP stack
to panic the kernel when receiving a crafted ACK response. Only Ubuntu
7.10 contained the vulnerable code, and it is believed not to have
been exploitable. (CVE-2007-5501)

When mounting the same remote NFS share to separate local locations,
the first location's mount options would apply to all subsequent
mounts of the same NFS share. In some configurations, this could lead
to incorrectly configured permissions, allowing local users to gain
additional access to the mounted share.
(https://launchpad.net/bugs/164231)

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
  script_cwe_id(20, 189, 264, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/17");
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
if (! ereg(pattern:"^(6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.10", pkgname:"linux-doc-2.6.17", pkgver:"2.6.17.1-12.42")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12", pkgver:"2.6.17.1-12.42")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12-386", pkgver:"2.6.17.1-12.42")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12-generic", pkgver:"2.6.17.1-12.42")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12-server", pkgver:"2.6.17.1-12.42")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-12-386", pkgver:"2.6.17.1-12.42")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-12-generic", pkgver:"2.6.17.1-12.42")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-12-server", pkgver:"2.6.17.1-12.42")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-12-386", pkgver:"2.6.17.1-12.42")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-12-generic", pkgver:"2.6.17.1-12.42")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-12-server", pkgver:"2.6.17.1-12.42")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-kdump", pkgver:"2.6.17.1-12.42")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-kernel-devel", pkgver:"2.6.17.1-12.42")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-libc-dev", pkgver:"2.6.17.1-12.42")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-source-2.6.17", pkgver:"2.6.17.1-12.42")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-doc-2.6.20", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-386", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-generic", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-lowlatency", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-server", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-386", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-generic", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-lowlatency", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-server", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-386", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-generic", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-lowlatency", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-server", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-kernel-devel", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-libc-dev", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-source-2.6.20", pkgver:"2.6.20-16.33")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-doc-2.6.22", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-386", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-generic", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-rt", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-server", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-ume", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-virtual", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-14-xen", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-386", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-cell", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-generic", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-lpia", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-lpiacompat", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-rt", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-server", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-ume", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-virtual", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-14-xen", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-14-386", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-14-generic", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-14-server", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-14-virtual", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-kernel-devel", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-libc-dev", pkgver:"2.6.22-14.47")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-source-2.6.22", pkgver:"2.6.22-14.47")) flag++;

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
