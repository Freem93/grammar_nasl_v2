#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1767-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65609);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/26 14:05:58 $");

  script_cve_id("CVE-2013-0190", "CVE-2013-0216", "CVE-2013-0217", "CVE-2013-0228", "CVE-2013-0231", "CVE-2013-0268", "CVE-2013-0311", "CVE-2013-0313", "CVE-2013-0349", "CVE-2013-1774");
  script_osvdb_id(89336, 89901, 89902, 89903, 90003, 90186, 90478, 90480, 90553, 90678);
  script_xref(name:"USN", value:"1767-1");

  script_name(english:"Ubuntu 12.04 LTS : linux vulnerabilities (USN-1767-1)");
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
"Andrew Cooper of Citrix reported a Xen stack corruption in the Linux
kernel. An unprivileged user in a 32bit PVOPS guest can cause the
guest kernel to crash, or operate erroneously. (CVE-2013-0190)

A failure to validate input was discovered in the Linux kernel's Xen
netback (network backend) driver. A user in a guest OS may exploit
this flaw to cause a denial of service to the guest OS and other guest
domains. (CVE-2013-0216)

A memory leak was discovered in the Linux kernel's Xen netback
(network backend) driver. A user in a guest OS could trigger this flaw
to cause a denial of service on the system. (CVE-2013-0217)

Andrew Jones discovered a flaw with the xen_iret function in Linux
kernel's Xen virtualizeation. In the 32-bit Xen paravirt platform an
unprivileged guest OS user could exploit this flaw to cause a denial
of service (crash the system) or gain guest OS privilege.
(CVE-2013-0228)

A flaw was discovered in the Linux kernel Xen PCI backend driver. If a
PCI device is assigned to the guest OS, the guest OS could exploit
this flaw to cause a denial of service on the host. (CVE-2013-0231)

A flaw was reported in the permission checks done by the Linux kernel
for /dev/cpu/*/msr. A local root user with all capabilities dropped
could exploit this flaw to execute code with full root capabilities.
(CVE-2013-0268)

A flaw was discovered in the Linux kernel's vhost driver used to
accelerate guest networking in KVM based virtual machines. A
privileged guest user could exploit this flaw to crash the host
system. (CVE-2013-0311)

A flaw was discovered in the Extended Verification Module (EVM) of the
Linux kernel. An unprivileged local user code exploit this flaw to
cause a denial of service (system crash). (CVE-2013-0313)

An information leak was discovered in the Linux kernel's Bluetooth
stack when HIDP (Human Interface Device Protocol) support is enabled.
A local unprivileged user could exploit this flaw to cause an
information leak from the kernel. (CVE-2013-0349)

A flaw was discovered in the Edgeort USB serial converter driver when
the device is disconnected while it is in use. A local user could
exploit this flaw to cause a denial of service (system crash).
(CVE-2013-1774).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/19");
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
if (! ereg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-39-generic", pkgver:"3.2.0-39.62")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-39-generic-pae", pkgver:"3.2.0-39.62")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-39-highbank", pkgver:"3.2.0-39.62")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-39-virtual", pkgver:"3.2.0-39.62")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.2-generic / linux-image-3.2-generic-pae / etc");
}
