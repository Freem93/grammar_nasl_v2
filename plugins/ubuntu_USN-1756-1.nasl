#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1756-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65077);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/26 14:05:58 $");

  script_cve_id("CVE-2013-0216", "CVE-2013-0217", "CVE-2013-0228", "CVE-2013-0268", "CVE-2013-0311", "CVE-2013-0349", "CVE-2013-1773");
  script_bugtraq_id(57743, 57744, 57838, 57940, 58053, 58200);
  script_osvdb_id(89901, 89902, 90003, 90186, 90478, 90553, 90675);
  script_xref(name:"USN", value:"1756-1");

  script_name(english:"Ubuntu 11.10 : linux vulnerabilities (USN-1756-1)");
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
"A failure to validate input was discovered in the Linux kernel's Xen
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

A flaw was reported in the permission checks done by the Linux kernel
for /dev/cpu/*/msr. A local root user with all capabilities dropped
could exploit this flaw to execute code with full root capabilities.
(CVE-2013-0268)

A flaw was discovered in the Linux kernel's vhost driver used to
accelerate guest networking in KVM based virtual machines. A
privileged guest user could exploit this flaw to crash the host
system. (CVE-2013-0311)

An information leak was discovered in the Linux kernel's Bluetooth
stack when HIDP (Human Interface Device Protocol) support is enabled.
A local unprivileged user could exploit this flaw to cause an
information leak from the kernel. (CVE-2013-0349)

A flaw was discovered on the Linux kernel's VFAT filesystem driver
when a disk is mounted with the utf8 option (this is the default on
Ubuntu). On a system where disks/images can be auto-mounted or a FAT
filesystem is mounted an unprivileged user can exploit the flaw to
gain root privileges. (CVE-2013-1773).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.0-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.0-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.0-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.0-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/07");
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
if (! ereg(pattern:"^(11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"11.10", pkgname:"linux-image-3.0.0-32-generic", pkgver:"3.0.0-32.50")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"linux-image-3.0.0-32-generic-pae", pkgver:"3.0.0-32.50")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"linux-image-3.0.0-32-server", pkgver:"3.0.0-32.50")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"linux-image-3.0.0-32-virtual", pkgver:"3.0.0-32.50")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.0-generic / linux-image-3.0-generic-pae / etc");
}
