#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2023-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70805);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/26 14:16:25 $");

  script_cve_id("CVE-2013-0343", "CVE-2013-2147", "CVE-2013-2889", "CVE-2013-2893", "CVE-2013-2894", "CVE-2013-2895", "CVE-2013-2897", "CVE-2013-4343");
  script_bugtraq_id(58795, 60280, 62042, 62044, 62045, 62050, 62052, 62360);
  script_osvdb_id(90811, 94027, 96766, 96770, 96772, 96773, 96774, 97236);
  script_xref(name:"USN", value:"2023-1");

  script_name(english:"Ubuntu 13.04 : linux vulnerabilities (USN-2023-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An information leak was discovered in the handling of ICMPv6 Router
Advertisement (RA) messages in the Linux kernel's IPv6 network stack.
A remote attacker could exploit this flaw to cause a denial of service
(excessive retries and address-generation outage), and consequently
obtain sensitive information. (CVE-2013-0343)

Dan Carpenter discovered an information leak in the HP Smart Aray and
Compaq SMART2 disk-array driver in the Linux kernel. A local user
could exploit this flaw to obtain sensitive information from kernel
memory. (CVE-2013-2147)

Kees Cook discovered flaw in the Human Interface Device (HID)
subsystem when CONFIG_HID_ZEROPLUS is enabled. A physically proximate
attacker could leverage this flaw to cause a denial of service via a
specially crafted device. (CVE-2013-2889)

Kees Cook discovered another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when any of CONFIG_LOGITECH_FF,
CONFIG_LOGIG940_FF, or CONFIG_LOGIWHEELS_FF are enabled. A physcially
proximate attacker can leverage this flaw to cause a denial of service
vias a specially crafted device. (CVE-2013-2893)

Kees Cook discovered a flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when CONFIG_HID_LENOVO_TPKBD is enabled.
A physically proximate attacker could exploit this flaw to cause a
denial of service via a specially crafted device. (CVE-2013-2894)

Kees Cook discovered another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when CONFIG_HID_LOGITECH_DJ is enabled.
A physically proximate attacker could cause a denial of service (OOPS)
or obtain sensitive information from kernel memory via a specially
crafted device. (CVE-2013-2895)

Kees Cook discovered yet another flaw in the Human Interface Device
(HID) subsystem of the Linux kernel when CONFIG_HID_MULTITOUCH is
enabled. A physically proximate attacker could leverage this flaw to
cause a denial of service (OOPS) via a specially crafted device.
(CVE-2013-2897)

Wannes Rombouts reported a vulnerability in the networking tuntap
interface of the Linux kernel. A local user with the CAP_NET_ADMIN
capability could leverage this flaw to gain full admin privileges.
(CVE-2013-4343).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected linux-image-3.8-generic package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.8-generic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/09");
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
if (! ereg(pattern:"^(13\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 13.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"13.04", pkgname:"linux-image-3.8.0-33-generic", pkgver:"3.8.0-33.48")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.8-generic");
}
