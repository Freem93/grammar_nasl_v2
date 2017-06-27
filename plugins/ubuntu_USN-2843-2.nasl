#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2843-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87497);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2015-7799", "CVE-2015-7872", "CVE-2015-7884", "CVE-2015-7885", "CVE-2015-8104");
  script_osvdb_id(128845, 129330, 129371, 129372, 130089);
  script_xref(name:"USN", value:"2843-2");

  script_name(english:"Ubuntu 14.04 LTS : linux-lts-wily vulnerabilities (USN-2843-2)");
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
"Jan Beulich discovered that the KVM svm hypervisor implementation in
the Linux kernel did not properly catch Debug exceptions on AMD
processors. An attacker in a guest virtual machine could use this to
cause a denial of service (system crash) in the host OS.
(CVE-2015-8104)

Guoyong Gang discovered that the ppp implementation in the Linux
kernel did not ensure that certain slot numbers are valid. A local
attacker with the privilege to call ioctl() on /dev/ppp could cause a
denial of service (system crash). (CVE-2015-7799)

Dmitry Vyukov discovered that the Linux kernel's keyring handler
attempted to garbage collect incompletely instantiated keys. A local
unprivileged attacker could use this to cause a denial of service
(system crash). (CVE-2015-7872)

It was discovered that the virtual video osd test driver in the Linux
kernel did not properly initialize data structures. A local attacker
could use this to obtain sensitive information from the kernel.
(CVE-2015-7884)

It was discovered that the driver for Digi Neo and ClassicBoard
devices did not properly initialize data structures. A local attacker
could use this to obtain sensitive information from the kernel.
(CVE-2015-7885).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-4.2-generic,
linux-image-4.2-generic-lpae and / or linux-image-4.2-lowlatency
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.2-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.2-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.2-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/18");
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

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.2.0-21-generic", pkgver:"4.2.0-21.25~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.2.0-21-generic-lpae", pkgver:"4.2.0-21.25~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.2.0-21-lowlatency", pkgver:"4.2.0-21.25~14.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.2-generic / linux-image-4.2-generic-lpae / etc");
}
