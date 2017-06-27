#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-670-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37886);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:37:17 $");

  script_cve_id("CVE-2008-5103", "CVE-2008-5104");
  script_osvdb_id(49996);
  script_xref(name:"USN", value:"670-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : vm-builder vulnerability (USN-670-1)");
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
"Mathias Gug discovered that vm-builder improperly set the root
password when creating virtual machines. An attacker could exploit
this to gain root privileges to the virtual machine by using a
predictable password.

This vulnerability only affects virtual machines created with
vm-builder under Ubuntu 8.10, and does not affect native Ubuntu
installations. An update was made to the shadow package to detect
vulnerable systems and disable password authentication for the root
account. Vulnerable virtual machines which an attacker has access to
should be considered compromised, and appropriate actions taken to
secure the machine.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:TF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:login");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:passwd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-vm-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-vm-builder-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ubuntu-vm-builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.10|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.10 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"login", pkgver:"4.0.13-7ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"passwd", pkgver:"1:4.0.13-7ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"login", pkgver:"4.0.18.1-9ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"passwd", pkgver:"1:4.0.18.1-9ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"login", pkgver:"4.0.18.2-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"passwd", pkgver:"1:4.0.18.2-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"login", pkgver:"4.1.1-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"passwd", pkgver:"1:4.1.1-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-vm-builder", pkgver:"0.9-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-vm-builder-ec2", pkgver:"0.9-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ubuntu-vm-builder", pkgver:"0.9-0ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "login / passwd / python-vm-builder / python-vm-builder-ec2 / etc");
}
