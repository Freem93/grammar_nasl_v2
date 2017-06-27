#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2443-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80030);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/26 14:16:26 $");

  script_cve_id("CVE-2014-7825", "CVE-2014-7826", "CVE-2014-7841", "CVE-2014-8134", "CVE-2014-8884", "CVE-2014-9090");
  script_bugtraq_id(70971, 70972, 71081, 71097, 71250);
  script_osvdb_id(114369, 114370, 114575, 114957, 115163, 115870);
  script_xref(name:"USN", value:"2443-1");

  script_name(english:"Ubuntu 12.04 LTS : linux vulnerabilities (USN-2443-1)");
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
"An information leak in the Linux kernel was discovered that could leak
the high 16 bits of the kernel stack address on 32-bit Kernel Virtual
Machine (KVM) paravirt guests. A user in the guest OS could exploit
this leak to obtain information that could potentially be used to aid
in attacking the kernel. (CVE-2014-8134)

Rabin Vincent, Robert Swiecki, Russell King discovered that the ftrace
subsystem of the Linux kernel does not properly handle private syscall
numbers. A local user could exploit this flaw to cause a denial of
service (OOPS). (CVE-2014-7826)

Rabin Vincent, Robert Swiecki, Russell Kinglaw discovered a flaw in
how the perf subsystem of the Linux kernel handles private systecall
numbers. A local user could exploit this to cause a denial of service
(OOPS) or bypass ASLR protections via a crafted application.
(CVE-2014-7825)

A NULL pointer dereference flaw was discovered in the the Linux
kernel's SCTP implementation when ASCONF is used. A remote attacker
could exploit this flaw to cause a denial of service (system crash)
via a malformed INIT chunk. (CVE-2014-7841)

A stack buffer overflow was discovered in the ioctl command handling
for the Technotrend/Hauppauge USB DEC devices driver. A local user
could exploit this flaw to cause a denial of service (system crash) or
possibly gain privileges. (CVE-2014-8884)

Andy Lutomirski discovered that the Linux kernel does not properly
handle faults associated with the Stack Segment (SS) register on the
x86 architecture. A local attacker could exploit this flaw to cause a
denial of service (panic). (CVE-2014-9090).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-74-generic", pkgver:"3.2.0-74.109")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-74-generic-pae", pkgver:"3.2.0-74.109")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-74-highbank", pkgver:"3.2.0-74.109")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-74-virtual", pkgver:"3.2.0-74.109")) flag++;

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
