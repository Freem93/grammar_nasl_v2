#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2515-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81568);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/10/26 14:16:27 $");

  script_cve_id("CVE-2014-8133", "CVE-2014-8160", "CVE-2014-8559", "CVE-2014-8989", "CVE-2014-9419", "CVE-2014-9420", "CVE-2014-9428", "CVE-2014-9529", "CVE-2014-9584", "CVE-2014-9585", "CVE-2014-9683", "CVE-2015-0239");
  script_bugtraq_id(70854, 71154, 71684, 71717, 71794, 71847, 71880, 71883, 71990, 72061, 72643, 72842);
  script_osvdb_id(114044, 114958, 115920, 116075, 116259, 116598, 116762, 116767, 116910, 117131, 117762, 118625);
  script_xref(name:"USN", value:"2515-1");

  script_name(english:"Ubuntu 12.04 LTS : linux-lts-trusty vulnerabilities (USN-2515-1)");
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
"A flaw was discovered in the Kernel Virtual Machine's (KVM) emulation
of the SYSTENTER instruction when the guest OS does not initialize the
SYSENTER MSRs. A guest OS user could exploit this flaw to cause a
denial of service of the guest OS (crash) or potentially gain
privileges on the guest OS. (CVE-2015-0239)

Andy Lutomirski discovered an information leak in the Linux kernel's
Thread Local Storage (TLS) implementation allowing users to bypass the
espfix to obtain information that could be used to bypass the Address
Space Layout Randomization (ASLR) protection mechanism. A local user
could exploit this flaw to obtain potentially sensitive information
from kernel memory. (CVE-2014-8133)

A restriction bypass was discovered in iptables when conntrack rules
are specified and the conntrack protocol handler module is not loaded
into the Linux kernel. This flaw can cause the firewall rules on the
system to be bypassed when conntrack rules are used. (CVE-2014-8160)

A flaw was discovered with file renaming in the linux kernel. A local
user could exploit this flaw to cause a denial of service (deadlock
and system hang). (CVE-2014-8559)

A flaw was discovered in how supplemental group memberships are
handled in certain namespace scenarios. A local user could exploit
this flaw to bypass file permission restrictions. (CVE-2014-8989)

A flaw was discovered in how Thread Local Storage (TLS) is handled by
the task switching function in the Linux kernel for x86_64 based
machines. A local user could exploit this flaw to bypass the Address
Space Layout Radomization (ASLR) protection mechanism. (CVE-2014-9419)

Prasad J Pandit reported a flaw in the rock_continue function of the
Linux kernel's ISO 9660 CDROM file system. A local user could exploit
this flaw to cause a denial of service (system crash or hang).
(CVE-2014-9420)

A flaw was discovered in the fragment handling of the B.A.T.M.A.N.
Advanced Meshing Protocol in the Linux kernel. A remote attacker could
exploit this flaw to cause a denial of service (mesh-node system
crash) via fragmented packets. (CVE-2014-9428)

A race condition was discovered in the Linux kernel's key ring. A
local user could cause a denial of service (memory corruption or
panic) or possibly have unspecified impact via the keyctl commands.
(CVE-2014-9529)

A memory leak was discovered in the ISO 9660 CDROM file system when
parsing rock ridge ER records. A local user could exploit this flaw to
obtain sensitive information from kernel memory via a crafted iso9660
image. (CVE-2014-9584)

A flaw was discovered in the Address Space Layout Randomization (ASLR)
of the Virtual Dynamically linked Shared Objects (vDSO) location. This
flaw makes it easier for a local user to bypass the ASLR protection
mechanism. (CVE-2014-9585)

Dmitry Chernenkov discovered a buffer overflow in eCryptfs' encrypted
file name decoding. A local unprivileged user could exploit this flaw
to cause a denial of service (system crash) or potentially gain
administrative privileges. (CVE-2014-9683).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.13-generic and / or
linux-image-3.13-generic-lpae packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.13.0-46-generic", pkgver:"3.13.0-46.75~precise1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.13.0-46-generic-lpae", pkgver:"3.13.0-46.75~precise1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.13-generic / linux-image-3.13-generic-lpae");
}
