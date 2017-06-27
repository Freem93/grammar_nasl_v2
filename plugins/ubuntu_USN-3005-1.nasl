#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3005-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91567);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/01 21:07:49 $");

  script_cve_id("CVE-2015-8839", "CVE-2016-1583", "CVE-2016-2117", "CVE-2016-2187", "CVE-2016-3961", "CVE-2016-4485", "CVE-2016-4486", "CVE-2016-4558", "CVE-2016-4565", "CVE-2016-4581");
  script_osvdb_id(135961, 136586, 137140, 137841, 137988, 138086, 138093, 138176, 138446, 139987);
  script_xref(name:"USN", value:"3005-1");

  script_name(english:"Ubuntu 14.04 LTS : linux-lts-xenial vulnerabilities (USN-3005-1)");
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
"Justin Yackoski discovered that the Atheros L2 Ethernet Driver in the
Linux kernel incorrectly enables scatter/gather I/O. A remote attacker
could use this to obtain potentially sensitive information from kernel
memory. (CVE-2016-2117)

Jann Horn discovered that eCryptfs improperly attempted to use the
mmap() handler of a lower filesystem that did not implement one,
causing a recursive page fault to occur. A local unprivileged attacker
could use to cause a denial of service (system crash) or possibly
execute arbitrary code with administrative privileges. (CVE-2016-1583)

Multiple race conditions where discovered in the Linux kernel's ext4
file system. A local user could exploit this flaw to cause a denial of
service (disk corruption) by writing to a page that is associated with
a different users file after unsynchronized hole punching and
page-fault handling. (CVE-2015-8839)

Ralf Spenneberg discovered that the Linux kernel's GTCO digitizer USB
device driver did not properly validate endpoint descriptors. An
attacker with physical access could use this to cause a denial of
service (system crash). (CVE-2016-2187)

Vitaly Kuznetsov discovered that the Linux kernel did not properly
suppress hugetlbfs support in X86 paravirtualized guests. An attacker
in the guest OS could cause a denial of service (guest system crash).
(CVE-2016-3961)

Kangjie Lu discovered an information leak in the ANSI/IEEE 802.2 LLC
type 2 Support implementations in the Linux kernel. A local attacker
could use this to obtain potentially sensitive information from kernel
memory. (CVE-2016-4485)

Kangjie Lu discovered an information leak in the routing netlink
socket interface (rtnetlink) implementation in the Linux kernel. A
local attacker could use this to obtain potentially sensitive
information from kernel memory. (CVE-2016-4486)

Jann Horn discovered that the extended Berkeley Packet Filter (eBPF)
implementation in the Linux kernel could overflow reference counters
on systems with more than 32GB of physical ram and with RLIMIT_MEMLOCK
set to infinite. A local unprivileged attacker could use to create a
use-after- free situation, causing a denial of service (system crash)
or possibly gain administrative privileges. (CVE-2016-4558)

Jann Horn discovered that the InfiniBand interfaces within the Linux
kernel could be coerced into overwriting kernel memory. A local
unprivileged attacker could use this to possibly gain administrative
privileges on systems where InifiniBand related kernel modules are
loaded. (CVE-2016-4565)

It was discovered that in some situations the Linux kernel did not
handle propagated mounts correctly. A local unprivileged attacker
could use this to cause a denial of service (system crash).
(CVE-2016-4581).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-4.4-generic,
linux-image-4.4-generic-lpae and / or linux-image-4.4-lowlatency
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:X/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-24-generic", pkgver:"4.4.0-24.43~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-24-generic-lpae", pkgver:"4.4.0-24.43~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-24-lowlatency", pkgver:"4.4.0-24.43~14.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.4-generic / linux-image-4.4-generic-lpae / etc");
}
