#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2491-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81164);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/26 14:16:27 $");

  script_cve_id("CVE-2014-3610", "CVE-2014-3611", "CVE-2014-8133", "CVE-2014-9322", "CVE-2014-9420");
  script_bugtraq_id(70742, 70743, 71684, 71685, 71717);
  script_osvdb_id(113823, 115919, 115920, 116075);
  script_xref(name:"USN", value:"2491-1");

  script_name(english:"Ubuntu 10.04 LTS : linux-ec2 vulnerabilities (USN-2491-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Andy Lutomirski discovered that the Linux kernel does not properly
handle faults associated with the Stack Segment (SS) register in the
x86 architecture. A local attacker could exploit this flaw to gain
administrative privileges. (CVE-2014-9322)

Lars Bull reported a race condition in the PIT (programmable interrupt
timer) emulation in the KVM (Kernel Virtual Machine) subsystem of the
Linux kernel. A local guest user with access to PIT i/o ports could
exploit this flaw to cause a denial of service (crash) on the host.
(CVE-2014-3611)

Lars Bull and Nadav Amit reported a flaw in how KVM (the Kernel
Virtual Machine) handles noncanonical writes to certain MSR registers.
A privileged guest user can exploit this flaw to cause a denial of
service (kernel panic) on the host. (CVE-2014-3610)

Andy Lutomirski discovered an information leak in the Linux kernel's
Thread Local Storage (TLS) implementation allowing users to bypass the
espfix to obtain information that could be used to bypass the Address
Space Layout Randomization (ASLR) protection mechanism. A local user
could exploit this flaw to obtain potentially sensitive information
from kernel memory. (CVE-2014-8133)

Prasad J Pandit reported a flaw in the rock_continue function of the
Linux kernel's ISO 9660 CDROM file system. A local user could exploit
this flaw to cause a denial of service (system crash or hang).
(CVE-2014-9420).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected linux-image-2.6-ec2 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-ec2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/04");
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
if (! ereg(pattern:"^(10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-375-ec2", pkgver:"2.6.32-375.92")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-2.6-ec2");
}
