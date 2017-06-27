#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-578-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31093);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2006-6058", "CVE-2006-7229", "CVE-2007-4133", "CVE-2007-4997", "CVE-2007-5093", "CVE-2007-5500", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6417", "CVE-2008-0001");
  script_bugtraq_id(26337, 26477, 26605, 26701, 27280, 27497, 27694);
  script_osvdb_id(40913, 44120, 45283);
  script_xref(name:"USN", value:"578-1");

  script_name(english:"Ubuntu 6.06 LTS : linux-source-2.6.15 vulnerabilities (USN-578-1)");
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

Alexander Schulze discovered that the skge driver does not properly
use the spin_lock and spin_unlock functions. Remote attackers could
exploit this by sending a flood of network traffic and cause a denial
of service (crash). (CVE-2006-7229)

Hugh Dickins discovered that hugetlbfs performed certain prio_tree
calculations using HPAGE_SIZE instead of PAGE_SIZE. A local user could
exploit this and cause a denial of service via kernel panic.
(CVE-2007-4133)

Chris Evans discovered an issue with certain drivers that use the
ieee80211_rx function. Remote attackers could send a crafted 802.11
frame and cause a denial of service via crash. (CVE-2007-4997)

Alex Smith discovered an issue with the pwc driver for certain webcam
devices. A local user with physical access to the system could remove
the device while a userspace application had it open and cause the USB
subsystem to block. (CVE-2007-5093)

Scott James Remnant discovered a coding error in ptrace. Local users
could exploit this and cause the kernel to enter an infinite loop.
(CVE-2007-5500)

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
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 119, 189, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/14");
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
if (! ereg(pattern:"^(6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-51", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-51-386", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-51-686", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-51-amd64-generic", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-51-amd64-k8", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-51-amd64-server", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-51-amd64-xeon", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-51-server", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-51-386", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-51-686", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-51-amd64-generic", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-51-amd64-k8", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-51-amd64-server", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-51-amd64-xeon", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-51-server", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-51.66")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-51.66")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.15 / linux-headers-2.6 / linux-headers-2.6-386 / etc");
}
