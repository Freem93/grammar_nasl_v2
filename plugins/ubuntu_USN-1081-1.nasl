#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1081-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52500);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/26 14:05:56 $");

  script_cve_id("CVE-2010-3698", "CVE-2010-3865", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-4079", "CVE-2010-4083", "CVE-2010-4248", "CVE-2010-4250", "CVE-2010-4342", "CVE-2010-4346", "CVE-2010-4527", "CVE-2010-4648", "CVE-2010-4649", "CVE-2010-4650", "CVE-2011-0006", "CVE-2011-1044", "CVE-2011-4621");
  script_bugtraq_id(44549, 44630, 44665, 45028, 45062, 45321, 45323, 45629, 46073, 46488);
  script_xref(name:"USN", value:"1081-1");

  script_name(english:"Ubuntu 10.10 : linux vulnerabilities (USN-1081-1)");
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
"It was discovered that KVM did not correctly initialize certain CPU
registers. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2010-3698)

Thomas Pollet discovered that the RDS network protocol did not check
certain iovec buffers. A local attacker could exploit this to crash
the system or possibly execute arbitrary code as the root user.
(CVE-2010-3865)

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

Dan Rosenberg discovered that the ivtv V4L driver did not correctly
initialize certian structures. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4079)

Dan Rosenberg discovered that the semctl syscall did not correctly
clear kernel memory. A local attacker could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-4083)

It was discovered that multithreaded exec did not handle CPU timers
correctly. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2010-4248)

Vegard Nossum discovered a leak in the kernel's inotify_init() system
call. A local, unprivileged user could exploit this to cause a denial
of service. (CVE-2010-4250)

Nelson Elhage discovered that Econet did not correctly handle AUN
packets over UDP. A local attacker could send specially crafted
traffic to crash the system, leading to a denial of service.
(CVE-2010-4342)

Tavis Ormandy discovered that the install_special_mapping function
could bypass the mmap_min_addr restriction. A local attacker could
exploit this to mmap 4096 bytes below the mmap_min_addr area, possibly
improving the chances of performing NULL pointer dereference attacks.
(CVE-2010-4346)

Dan Rosenberg discovered that the OSS subsystem did not handle name
termination correctly. A local attacker could exploit this crash the
system or gain root privileges. (CVE-2010-4527)

An error was reported in the kernel's ORiNOCO wireless driver's
handling of TKIP countermeasures. This reduces the amount of time an
attacker needs breach a wireless network using WPA+TKIP for security.
(CVE-2010-4648)

Dan Carpenter discovered that the Infiniband driver did not correctly
handle certain requests. A local user could exploit this to crash the
system or potentially gain root privileges. (CVE-2010-4649,
CVE-2011-1044)

An error was discovered in the kernel's handling of CUSE (Character
device in Userspace). A local attacker might exploit this flaw to
escalate privilege, if access to /dev/cuse has been modified to allow
non-root users. (CVE-2010-4650)

A flaw was found in the kernel's Integrity Measurement Architecture
(IMA). Changes made by an attacker might not be discovered by IMA, if
SELinux was disabled, and a new IMA rule was loaded. (CVE-2011-0006)

It was discovered that some import kernel threads can be blocked by a
user level process. An unprivileged local user could exploit this flaw
to cause a denial of service. (CVE-2011-4621).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/02");
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
if (! ereg(pattern:"^(10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.10", pkgname:"linux-doc", pkgver:"2.6.35-27.48")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-27", pkgver:"2.6.35-27.48")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-27-generic", pkgver:"2.6.35-27.48")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-27-generic-pae", pkgver:"2.6.35-27.48")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-27-server", pkgver:"2.6.35-27.48")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-headers-2.6.35-27-virtual", pkgver:"2.6.35-27.48")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-27-generic", pkgver:"2.6.35-27.48")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-27-generic-pae", pkgver:"2.6.35-27.48")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-27-server", pkgver:"2.6.35-27.48")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-27-versatile", pkgver:"2.6.35-27.48")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-27-virtual", pkgver:"2.6.35-27.48")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-libc-dev", pkgver:"2.6.35-1027.48")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-source-2.6.35", pkgver:"2.6.35-27.48")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-tools-2.6.35-27", pkgver:"2.6.35-27.48")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"linux-tools-common", pkgver:"2.6.35-27.48")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc / linux-headers-2.6 / linux-headers-2.6-generic / etc");
}
