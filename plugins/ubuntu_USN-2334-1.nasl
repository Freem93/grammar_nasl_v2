#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2334-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77490);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/04/10 13:19:30 $");

  script_cve_id("CVE-2014-3917", "CVE-2014-4027", "CVE-2014-4171", "CVE-2014-4508", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-5077");
  script_bugtraq_id(67699, 67985, 68126, 68157, 68162, 68163, 68164, 68170, 68224, 68881);
  script_osvdb_id(108001, 108287, 108293, 108386, 108389, 108390, 108451, 108473, 109512);
  script_xref(name:"USN", value:"2334-1");

  script_name(english:"Ubuntu 12.04 LTS : linux vulnerabilities (USN-2334-1)");
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
"An flaw was discovered in the Linux kernel's audit subsystem when
auditing certain syscalls. A local attacker could exploit this flaw to
obtain potentially sensitive single-bit values from kernel memory or
cause a denial of service (OOPS). (CVE-2014-3917)

An information leak was discovered in the rd_mcp backend of the iSCSI
target subsystem in the Linux kernel. A local user could exploit this
flaw to obtain sensitive information from ramdisk_mcp memory by
leveraging access to a SCSI initiator. (CVE-2014-4027)

Sasha Levin reported an issue with the Linux kernel's shared memory
subsystem when used with range notifications and hole punching. A
local user could exploit this flaw to cause a denial of service.
(CVE-2014-4171)

Toralf Forster reported an error in the Linux kernels syscall
auditing on 32 bit x86 platforms. A local user could exploit this flaw
to cause a denial of service (OOPS and system crash). (CVE-2014-4508)

An information leak was discovered in the control implemenation of the
Advanced Linux Sound Architecture (ALSA) subsystem in the Linux
kernel. A local user could exploit this flaw to obtain sensitive
information from kernel memory. (CVE-2014-4652)

A use-after-free flaw was discovered in the Advanced Linux Sound
Architecture (ALSA) control implementation of the Linux kernel. A
local user could exploit this flaw to cause a denial of service
(system crash). (CVE-2014-4653)

A authorization bug was discovered with the snd_ctl_elem_add function
of the Advanced Linux Sound Architecture (ALSA) in the Linux kernel. A
local user could exploit his bug to cause a denial of service (remove
kernel controls). (CVE-2014-4654)

A flaw discovered in how the snd_ctl_elem function of the Advanced
Linux Sound Architecture (ALSA) handled a reference count. A local
user could exploit this flaw to cause a denial of service (integer
overflow and limit bypass). (CVE-2014-4655)

An integer overflow flaw was discovered in the control implementation
of the Advanced Linux Sound Architecture (ALSA). A local user could
exploit this flaw to cause a denial of service (system crash).
(CVE-2014-4656)

An integer underflow flaw was discovered in the Linux kernel's
handling of the backlog value for certain SCTP packets. A remote
attacker could exploit this flaw to cause a denial of service (socket
outage) via a crafted SCTP packet. (CVE-2014-4667)

Jason Gunthorpe reported a flaw with SCTP authentication in the Linux
kernel. A remote attacker could exploit this flaw to cause a denial of
service (NULL pointer dereference and OOPS). (CVE-2014-5077).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2017 Canonical, Inc. / NASL script (C) 2014-2017 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-68-generic", pkgver:"3.2.0-68.102")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-68-generic-pae", pkgver:"3.2.0-68.102")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-68-highbank", pkgver:"3.2.0-68.102")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-68-virtual", pkgver:"3.2.0-68.102")) flag++;

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
