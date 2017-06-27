#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1054-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51847);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/26 14:05:56 $");

  script_cve_id("CVE-2010-0435", "CVE-2010-3859", "CVE-2010-3873", "CVE-2010-3874", "CVE-2010-3881", "CVE-2010-4073", "CVE-2010-4079", "CVE-2010-4083", "CVE-2010-4158", "CVE-2010-4160", "CVE-2010-4162", "CVE-2010-4164", "CVE-2010-4165", "CVE-2010-4169", "CVE-2010-4175", "CVE-2010-4243", "CVE-2010-4249", "CVE-2010-4256", "CVE-2010-4258");
  script_xref(name:"USN", value:"1054-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 : linux, linux-ec2 vulnerabilities (USN-1054-1)");
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

Dan Rosenberg discovered that the Linux kernel TIPC implementation
contained multiple integer signedness errors. A local attacker could
exploit this to gain root privileges. (CVE-2010-3859)

Dan Rosenberg discovered that the Linux kernel X.25 implementation
incorrectly parsed facilities. A remote attacker could exploit this to
crash the kernel, leading to a denial of service. (CVE-2010-3873)

Dan Rosenberg discovered that the CAN protocol on 64bit systems did
not correctly calculate the size of certain buffers. A local attacker
could exploit this to crash the system or possibly execute arbitrary
code as the root user. (CVE-2010-3874)

Vasiliy Kulikov discovered that kvm did not correctly clear memory. A
local attacker could exploit this to read portions of the kernel
stack, leading to a loss of privacy. (CVE-2010-3881)

Dan Rosenberg discovered that IPC structures were not correctly
initialized on 64bit systems. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4073)

Dan Rosenberg discovered that the ivtv V4L driver did not correctly
initialize certian structures. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4079)

Dan Rosenberg discovered that the semctl syscall did not correctly
clear kernel memory. A local attacker could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-4083)

Dan Rosenberg discovered that the socket filters did not correctly
initialize structure memory. A local attacker could create malicious
filters to read portions of kernel stack memory, leading to a loss of
privacy. (CVE-2010-4158)

Dan Rosenberg discovered that the Linux kernel L2TP implementation
contained multiple integer signedness errors. A local attacker could
exploit this to to crash the kernel, or possibly gain root privileges.
(CVE-2010-4160)

Dan Rosenberg discovered that certain iovec operations did not
calculate page counts correctly. A local attacker could exploit this
to crash the system, leading to a denial of service. (CVE-2010-4162)

Dan Rosenberg discovered multiple flaws in the X.25 facilities
parsing. If a system was using X.25, a remote attacker could exploit
this to crash the system, leading to a denial of service.
(CVE-2010-4164)

Steve Chen discovered that setsockopt did not correctly check MSS
values. A local attacker could make a specially crafted socket call to
crash the system, leading to a denial of service. (CVE-2010-4165)

Dave Jones discovered that the mprotect system call did not correctly
handle merged VMAs. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-4169)

Dan Rosenberg discovered that the RDS protocol did not correctly check
ioctl arguments. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-4175)

Brad Spengler discovered that the kernel did not correctly account for
userspace memory allocations during exec() calls. A local attacker
could exploit this to consume all system memory, leading to a denial
of service. (CVE-2010-4243)

Vegard Nossum discovered that memory garbage collection was not
handled correctly for active sockets. A local attacker could exploit
this to allocate all available kernel memory, leading to a denial of
service. (CVE-2010-4249)

It was discovered that named pipes did not correctly handle certain
fcntl calls. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2010-4256)

Nelson Elhage discovered that the kernel did not correctly handle
process cleanup after triggering a recoverable kernel bug. If a local
attacker were able to trigger certain kinds of kernel bugs, they could
create a specially crafted process to gain root privileges.
(CVE-2010-4258).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ec2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-ec2-source-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/02");
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
if (! ereg(pattern:"^(10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"linux-doc", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-ec2-doc", pkgver:"2.6.32-312.24")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-ec2-source-2.6.32", pkgver:"2.6.32-312.24")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-28", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-28-386", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-28-generic", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-28-generic-pae", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-28-preempt", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-28-server", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-312", pkgver:"2.6.32-312.24")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-headers-2.6.32-312-ec2", pkgver:"2.6.32-312.24")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-28-386", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-28-generic", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-28-generic-pae", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-28-lpia", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-28-preempt", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-28-server", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-28-versatile", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-28-virtual", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-312-ec2", pkgver:"2.6.32-312.24")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-libc-dev", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-source-2.6.32", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-tools-2.6.32-28", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-tools-common", pkgver:"2.6.32-28.55")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-doc", pkgver:"2.6.35-25.44")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-25", pkgver:"2.6.35-25.44")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-25-generic", pkgver:"2.6.35-25.44")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-25-generic-pae", pkgver:"2.6.35-25.44")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-25-server", pkgver:"2.6.35-25.44")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-25-virtual", pkgver:"2.6.35-25.44")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-25-generic", pkgver:"2.6.35-25.44")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-25-generic-pae", pkgver:"2.6.35-25.44")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-25-server", pkgver:"2.6.35-25.44")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-25-versatile", pkgver:"2.6.35-25.44")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-25-virtual", pkgver:"2.6.35-25.44")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-libc-dev", pkgver:"2.6.35-1025.44")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-source-2.6.35", pkgver:"2.6.35-25.44")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-tools-2.6.35-25", pkgver:"2.6.35-25.44")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-tools-common", pkgver:"2.6.35-25.44")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc / linux-ec2-doc / linux-ec2-source-2.6.32 / etc");
}
