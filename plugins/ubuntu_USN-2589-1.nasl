#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2589-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83180);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/26 14:16:27 $");

  script_cve_id("CVE-2015-2150", "CVE-2015-2666", "CVE-2015-2830", "CVE-2015-2922");
  script_bugtraq_id(73014, 73183, 73699, 74315);
  script_xref(name:"USN", value:"2589-1");

  script_name(english:"Ubuntu 14.04 LTS : linux-lts-utopic vulnerabilities (USN-2589-1)");
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
"Jan Beulich discovered the Xen virtual machine subsystem of the Linux
kernel did not properly restrict access to PCI command registers. A
local guest user could exploit this flaw to cause a denial of service
(host crash). (CVE-2015-2150)

A stack overflow was discovered in the the microcode loader for the
intel x86 platform. A local attacker could exploit this flaw to cause
a denial of service (kernel crash) or to potentially execute code with
kernel privileges. (CVE-2015-2666)

A privilege escalation was discovered in the fork syscal vi the int80
entry on 64 bit kernels with 32 bit emulation support. An unprivileged
local attacker could exploit this flaw to increase their privileges on
the system. (CVE-2015-2830)

It was discovered that the Linux kernel's IPv6 networking stack has a
flaw that allows using route advertisement (RA) messages to set the
'hop_limit' to values that are too low. An unprivileged attacker on a
local network could exploit this flaw to cause a denial of service
(IPv6 messages dropped). (CVE-2015-2922).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.16-generic,
linux-image-3.16-generic-lpae and / or linux-image-3.16-lowlatency
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/01");
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
if (! ereg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.16.0-36-generic", pkgver:"3.16.0-36.48~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.16.0-36-generic-lpae", pkgver:"3.16.0-36.48~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.16.0-36-lowlatency", pkgver:"3.16.0-36.48~14.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.16-generic / linux-image-3.16-generic-lpae / etc");
}
