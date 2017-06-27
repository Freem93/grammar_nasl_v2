#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2070-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71796);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/26 14:16:25 $");

  script_cve_id("CVE-2013-2929", "CVE-2013-2930", "CVE-2013-4345", "CVE-2013-4348", "CVE-2013-4511", "CVE-2013-4513", "CVE-2013-4514", "CVE-2013-4515", "CVE-2013-4516", "CVE-2013-6378", "CVE-2013-6380", "CVE-2013-6383", "CVE-2013-6763", "CVE-2013-7026");
  script_bugtraq_id(62740, 63536, 63886, 63887, 64111, 64312, 64318);
  script_osvdb_id(98017, 99273, 99322, 99324, 99325, 99326, 99327, 99673, 99674, 99675, 100292, 100294, 100296, 100506, 100508, 100836);
  script_xref(name:"USN", value:"2070-1");

  script_name(english:"Ubuntu 12.04 LTS : linux-lts-saucy vulnerabilities (USN-2070-1)");
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
"Vasily Kulikov reported a flaw in the Linux kernel's implementation of
ptrace. An unprivileged local user could exploit this flaw to obtain
sensitive information from kernel memory. (CVE-2013-2929)

Dave Jones and Vince Weaver reported a flaw in the Linux kernel's per
event subsystem that allows normal users to enable function tracing.
An unprivileged local user could exploit this flaw to obtain
potentially sensitive information from the kernel. (CVE-2013-2930)

Stephan Mueller reported an error in the Linux kernel's ansi cprng
random number generator. This flaw makes it easier for a local
attacker to break cryptographic protections. (CVE-2013-4345)

Jason Wang discovered a bug in the network flow dissector in the Linux
kernel. A remote attacker could exploit this flaw to cause a denial of
service (infinite loop). (CVE-2013-4348)

Multiple integer overflow flaws were discovered in the Alchemy LCD
frame- buffer drivers in the Linux kernel. An unprivileged local user
could exploit this flaw to gain administrative privileges.
(CVE-2013-4511)

Nico Golde and Fabian Yamaguchi reported a buffer overflow in the Ozmo
Devices USB over WiFi devices. A local user could exploit this flaw to
cause a denial of service or possibly unspecified impact.
(CVE-2013-4513)

Nico Golde and Fabian Yamaguchi reported a flaw in the Linux kernel's
driver for Agere Systems HERMES II Wireless PC Cards. A local user
with the CAP_NET_ADMIN capability could exploit this flaw to cause a
denial of service or possibly gain administrative priviliges.
(CVE-2013-4514)

Nico Golde and Fabian Yamaguchi reported a flaw in the Linux kernel's
driver for Beceem WIMAX chipset based devices. An unprivileged local
user could exploit this flaw to obtain sensitive information from
kernel memory. (CVE-2013-4515)

Nico Golde and Fabian Yamaguchi reported a flaw in the Linux kernel's
driver for the SystemBase Multi-2/PCI serial card. An unprivileged
user could obtain sensitive information from kernel memory.
(CVE-2013-4516)

Nico Golde and Fabian Yamaguchi reported a flaw in the Linux kernel's
debugfs filesystem. An administrative local user could exploit this
flaw to cause a denial of service (OOPS). (CVE-2013-6378)

Nico Golde and Fabian Yamaguchi reported a flaw in the driver for
Adaptec AACRAID scsi raid devices in the Linux kernel. A local user
could use this flaw to cause a denial of service or possibly other
unspecified impact. (CVE-2013-6380)

A flaw was discovered in the Linux kernel's compat ioctls for Adaptec
AACRAID scsi raid devices. An unprivileged local user could send
administrative commands to these devices potentially compromising the
data stored on the device. (CVE-2013-6383)

Nico Golde reported a flaw in the Linux kernel's userspace IO (uio)
driver. A local user could exploit this flaw to cause a denial of
service (memory corruption) or possibly gain privileges.
(CVE-2013-6763)

A race condition flaw was discovered in the Linux kernel's ipc shared
memory implimentation. A local user could exploit this flaw to cause a
denial of service (system crash) or possibly have unspecied other
impacts. (CVE-2013-7026).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.11-generic and / or
linux-image-3.11-generic-lpae packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.11-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.11-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/05");
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

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.11.0-15-generic", pkgver:"3.11.0-15.23~precise1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.11.0-15-generic-lpae", pkgver:"3.11.0-15.23~precise1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.11-generic / linux-image-3.11-generic-lpae");
}
