#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1529-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61507);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/26 14:05:58 $");

  script_cve_id("CVE-2012-2119", "CVE-2012-2136", "CVE-2012-2137", "CVE-2012-2372", "CVE-2012-2373", "CVE-2012-3364", "CVE-2012-3375", "CVE-2012-3400", "CVE-2012-3511");
  script_bugtraq_id(53165, 54063, 54966);
  script_osvdb_id(82038, 82459, 83056, 83104, 83105, 83548, 83549, 83687, 84682);
  script_xref(name:"USN", value:"1529-1");

  script_name(english:"Ubuntu 12.04 LTS : linux vulnerabilities (USN-1529-1)");
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
"A flaw was discovered in the Linux kernel's macvtap device driver,
which is used in KVM (Kernel-based Virtual Machine) to create a
network bridge between host and guest. A privleged user in a guest
could exploit this flaw to crash the host, if the vhost_net module is
loaded with the experimental_zcopytx option enabled. (CVE-2012-2119)

An error was discovered in the Linux kernel's network TUN/TAP device
implementation. A local user with access to the TUN/TAP interface
(which is not available to unprivileged users until granted by a root
user) could exploit this flaw to crash the system or potential gain
administrative privileges. (CVE-2012-2136)

A flaw was found in how the Linux kernel's KVM (Kernel-based Virtual
Machine) subsystem handled MSI (Message Signaled Interrupts). A local
unprivileged user could exploit this flaw to cause a denial of service
or potentially elevate privileges. (CVE-2012-2137)

A flaw was found in the Linux kernel's Reliable Datagram Sockets (RDS)
protocol implementation. A local, unprivileged user could use this
flaw to cause a denial of service. (CVE-2012-2372)

Ulrich Obergfell discovered an error in the Linux kernel's memory
management subsystem on 32 bit PAE systems with more than 4GB of
memory installed. A local unprivileged user could exploit this flaw to
crash the system. (CVE-2012-2373)

Dan Rosenberg discovered flaws in the Linux kernel's NCI (Near Field
Communication Controller Interface). A remote attacker could exploit
these flaws to crash the system or potentially execute privileged
code. (CVE-2012-3364)

A flaw was discovered in the Linux kernel's epoll system call. An
unprivileged local user could use this flaw to crash the system.
(CVE-2012-3375)

Some errors where discovered in the Linux kernel's UDF file system,
which is used to mount some CD-ROMs and DVDs. An unprivileged local
user could use these flaws to crash the system. (CVE-2012-3400)

A flaw was discovered in the madvise feature of the Linux kernel's
memory subsystem. An unprivileged local use could exploit the flaw to
cause a denial of service (crash the system). (CVE-2012-3511).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2016 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-29-generic", pkgver:"3.2.0-29.46")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-29-generic-pae", pkgver:"3.2.0-29.46")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-29-highbank", pkgver:"3.2.0-29.46")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-29-virtual", pkgver:"3.2.0-29.46")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.2-generic / linux-image-3.2-generic-pae / etc");
}
