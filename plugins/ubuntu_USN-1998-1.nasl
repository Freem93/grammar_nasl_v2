#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1998-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70543);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/26 14:16:25 $");

  script_cve_id("CVE-2013-2237", "CVE-2013-2888", "CVE-2013-2892", "CVE-2013-2896", "CVE-2013-2898", "CVE-2013-2899", "CVE-2013-4300");
  script_bugtraq_id(60953, 62043, 62046, 62048, 62049, 62056, 62072);
  script_xref(name:"USN", value:"1998-1");

  script_name(english:"Ubuntu 13.04 : linux vulnerabilities (USN-1998-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An information leak was discovered in the Linux kernel when reading
broadcast messages from the notify_policy interface of the IPSec
key_socket. A local user could exploit this flaw to examine
potentially sensitive information in kernel memory. (CVE-2013-2237)

Kees Cook discovered flaw in the Human Interface Device (HID)
subsystem of the Linux kernel. A physically proximate attacker could
exploit this flaw to execute arbitrary code or cause a denial of
service (heap memory corruption) via a specially crafted device that
provides an invalid Report ID. (CVE-2013-2888)

Kees Cook discovered a flaw in the Human Interface Device (HID)
subsystem of the Linux kerenl when CONFIG_HID_PANTHERLORD is enabled.
A physically proximate attacker could cause a denial of service (heap
out-of-bounds write) via a specially crafted device. (CVE-2013-2892)

Kees Cook discovered a vulnerability in the Linux Kernel's Human
Interface Device (HID) subsystem's support for N-Trig touch screens. A
physically proximate attacker could exploit this flaw to cause a
denial of service (OOPS) via a specially crafted device.
(CVE-2013-2896)

Kees Cook discovered an information leak in the Linux kernel's Human
Interface Device (HID) subsystem when CONFIG_HID_SENSOR_HUB is
enabled. A physically proximate attacker could obtain potentially
sensitive information from kernel memory via a specially crafted
device. (CVE-2013-2898)

Kees Cook discovered a flaw in the Human Interface Device (HID)
subsystem of the Linux kernel whe CONFIG_HID_PICOLCD is enabled. A
physically proximate attacker could exploit this flaw to cause a
denial of service (OOPS) via a specially crafted device.
(CVE-2013-2899)

A flaw was discovered in how the Linux Kernel's networking stack
checks scm credentials when used with namespaces. A local attacker
could exploit this flaw to gain privileges. (CVE-2013-4300).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected linux-image-3.8-generic package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.8-generic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/22");
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

if (ubuntu_check(osver:"13.04", pkgname:"linux-image-3.8.0-32-generic", pkgver:"3.8.0-32.47")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.8-generic");
}
