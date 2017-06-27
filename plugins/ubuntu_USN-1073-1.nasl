#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1073-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52476);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/10/26 14:05:56 $");

  script_cve_id("CVE-2010-0435", "CVE-2010-3448", "CVE-2010-3698", "CVE-2010-3859", "CVE-2010-3865", "CVE-2010-3873", "CVE-2010-3874", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-4073", "CVE-2010-4074", "CVE-2010-4078", "CVE-2010-4079", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4082", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4160", "CVE-2010-4165", "CVE-2010-4169", "CVE-2010-4248", "CVE-2010-4249");
  script_bugtraq_id(38607, 42582, 43809, 43810, 43817, 44354, 44500, 44549, 44630, 44642, 44648, 44661, 44665, 44762, 44830, 44861, 45028, 45037, 45058, 45062, 45063, 45074);
  script_xref(name:"USN", value:"1073-1");

  script_name(english:"Ubuntu 9.10 : linux, linux-ec2 vulnerabilities (USN-1073-1)");
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
"Gleb Napatov discovered that KVM did not correctly check certain
privileged operations. A local attacker with access to a guest kernel
could exploit this to crash the host system, leading to a denial of
service. (CVE-2010-0435)

Dan Jacobson discovered that ThinkPad video output was not correctly
access controlled. A local attacker could exploit this to hang the
system, leading to a denial of service. (CVE-2010-3448)

It was discovered that KVM did not correctly initialize certain CPU
registers. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2010-3698)

Dan Rosenberg discovered that the Linux kernel TIPC implementation
contained multiple integer signedness errors. A local attacker could
exploit this to gain root privileges. (CVE-2010-3859)

Thomas Pollet discovered that the RDS network protocol did not check
certain iovec buffers. A local attacker could exploit this to crash
the system or possibly execute arbitrary code as the root user.
(CVE-2010-3865)

Dan Rosenberg discovered that the Linux kernel X.25 implementation
incorrectly parsed facilities. A remote attacker could exploit this to
crash the kernel, leading to a denial of service. (CVE-2010-3873)

Dan Rosenberg discovered that the CAN protocol on 64bit systems did
not correctly calculate the size of certain buffers. A local attacker
could exploit this to crash the system or possibly execute arbitrary
code as the root user. (CVE-2010-3874)

Vasiliy Kulikov discovered that the Linux kernel X.25 implementation
did not correctly clear kernel memory. A local attacker could exploit
this to read kernel stack memory, leading to a loss of privacy.
(CVE-2010-3875)

Vasiliy Kulikov discovered that the Linux kernel sockets
implementation did not properly initialize certain structures. A local
attacker could exploit this to read kernel stack memory, leading to a
loss of privacy. (CVE-2010-3876)

Vasiliy Kulikov discovered that the TIPC interface did not correctly
initialize certain structures. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy.
(CVE-2010-3877)

Nelson Elhage discovered that the Linux kernel IPv4 implementation did
not properly audit certain bytecodes in netlink messages. A local
attacker could exploit this to cause the kernel to hang, leading to a
denial of service. (CVE-2010-3880)

Dan Rosenberg discovered that IPC structures were not correctly
initialized on 64bit systems. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4073)

Dan Rosenberg discovered that the USB subsystem did not correctly
initialize certian structures. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4074)

Dan Rosenberg discovered that the SiS video driver did not correctly
clear kernel memory. A local attacker could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-4078)

Dan Rosenberg discovered that the ivtv V4L driver did not correctly
initialize certian structures. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4079)

Dan Rosenberg discovered that the RME Hammerfall DSP audio interface
driver did not correctly clear kernel memory. A local attacker could
exploit this to read kernel stack memory, leading to a loss of
privacy. (CVE-2010-4080, CVE-2010-4081)

Dan Rosenberg discovered that the VIA video driver did not correctly
clear kernel memory. A local attacker could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-4082)

Dan Rosenberg discovered that the semctl syscall did not correctly
clear kernel memory. A local attacker could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-4083)

James Bottomley discovered that the ICP vortex storage array
controller driver did not validate certain sizes. A local attacker on
a 64bit system could exploit this to crash the kernel, leading to a
denial of service. (CVE-2010-4157)

Dan Rosenberg discovered that the Linux kernel L2TP implementation
contained multiple integer signedness errors. A local attacker could
exploit this to to crash the kernel, or possibly gain root privileges.
(CVE-2010-4160)

Steve Chen discovered that setsockopt did not correctly check MSS
values. A local attacker could make a specially crafted socket call to
crash the system, leading to a denial of service. (CVE-2010-4165)

Dave Jones discovered that the mprotect system call did not correctly
handle merged VMAs. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-4169)

It was discovered that multithreaded exec did not handle CPU timers
correctly. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2010-4248)

Vegard Nossum discovered that memory garbage collection was not
handled correctly for active sockets. A local attacker could exploit
this to allocate all available kernel memory, leading to a denial of
service. (CVE-2010-4249).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ec2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ec2-source-2.6.31");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.31");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.10", pkgname:"linux-doc", pkgver:"2.6.31-22.73")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-ec2-doc", pkgver:"2.6.31-307.27")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-ec2-source-2.6.31", pkgver:"2.6.31-307.27")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22", pkgver:"2.6.31-22.73")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22-386", pkgver:"2.6.31-22.73")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22-generic", pkgver:"2.6.31-22.73")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22-generic-pae", pkgver:"2.6.31-22.73")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-22-server", pkgver:"2.6.31-22.73")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-307", pkgver:"2.6.31-307.27")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-headers-2.6.31-307-ec2", pkgver:"2.6.31-307.27")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-386", pkgver:"2.6.31-22.73")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-generic", pkgver:"2.6.31-22.73")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-generic-pae", pkgver:"2.6.31-22.73")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-lpia", pkgver:"2.6.31-22.73")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-server", pkgver:"2.6.31-22.73")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-22-virtual", pkgver:"2.6.31-22.73")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-image-2.6.31-307-ec2", pkgver:"2.6.31-307.27")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-libc-dev", pkgver:"2.6.31-22.73")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"linux-source-2.6.31", pkgver:"2.6.31-22.73")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc / linux-ec2-doc / linux-ec2-source-2.6.31 / etc");
}
