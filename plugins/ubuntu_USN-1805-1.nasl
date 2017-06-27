#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1805-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66171);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/26 14:05:58 $");

  script_cve_id("CVE-2012-6542", "CVE-2012-6544", "CVE-2012-6545", "CVE-2012-6546", "CVE-2012-6548", "CVE-2013-0228", "CVE-2013-0349", "CVE-2013-1774", "CVE-2013-1796");
  script_bugtraq_id(57940, 58112, 58202, 58607, 58989, 58990, 58991, 58992, 58994);
  script_osvdb_id(90186, 90553, 90678, 90962, 90964, 90965, 90967, 91563);
  script_xref(name:"USN", value:"1805-1");

  script_name(english:"Ubuntu 10.04 LTS : linux vulnerabilities (USN-1805-1)");
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
"Mathias Krause discovered an information leak in the Linux kernel's
getsockname implementation for Logical Link Layer (llc) sockets. A
local user could exploit this flaw to examine some of the kernel's
stack memory. (CVE-2012-6542)

Mathias Krause discovered information leaks in the Linux kernel's
Bluetooth Logical Link Control and Adaptation Protocol (L2CAP)
implementation. A local user could exploit these flaws to examine some
of the kernel's stack memory. (CVE-2012-6544)

Mathias Krause discovered information leaks in the Linux kernel's
Bluetooth RFCOMM protocol implementation. A local user could exploit
these flaws to examine parts of kernel memory. (CVE-2012-6545)

Mathias Krause discovered information leaks in the Linux kernel's
Asynchronous Transfer Mode (ATM) networking stack. A local user could
exploit these flaws to examine some parts of kernel memory.
(CVE-2012-6546)

Mathias Krause discovered an information leak in the Linux kernel's
UDF file system implementation. A local user could exploit this flaw
to examine some of the kernel's heap memory. (CVE-2012-6548)

Andrew Jones discovered a flaw with the xen_iret function in Linux
kernel's Xen virtualizeation. In the 32-bit Xen paravirt platform an
unprivileged guest OS user could exploit this flaw to cause a denial
of service (crash the system) or gain guest OS privilege.
(CVE-2013-0228)

An information leak was discovered in the Linux kernel's Bluetooth
stack when HIDP (Human Interface Device Protocol) support is enabled.
A local unprivileged user could exploit this flaw to cause an
information leak from the kernel. (CVE-2013-0349)

A flaw was discovered in the Edgeort USB serial converter driver when
the device is disconnected while it is in use. A local user could
exploit this flaw to cause a denial of service (system crash).
(CVE-2013-1774)

Andrew Honig discovered a flaw in guest OS time updates in the Linux
kernel's KVM (Kernel-based Virtual Machine). A privileged guest user
could exploit this flaw to cause a denial of service (crash host
system) or potential escalate privilege to the host kernel level.
(CVE-2013-1796).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-46-386", pkgver:"2.6.32-46.108")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-46-generic", pkgver:"2.6.32-46.108")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-46-generic-pae", pkgver:"2.6.32-46.108")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-46-lpia", pkgver:"2.6.32-46.108")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-46-preempt", pkgver:"2.6.32-46.108")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-46-server", pkgver:"2.6.32-46.108")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-46-versatile", pkgver:"2.6.32-46.108")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-46-virtual", pkgver:"2.6.32-46.108")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-2.6-386 / linux-image-2.6-generic / etc");
}
