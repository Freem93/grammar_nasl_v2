#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-969-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48262);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2009-4901", "CVE-2009-4902", "CVE-2010-0407");
  script_bugtraq_id(40758);
  script_xref(name:"USN", value:"969-1");

  script_name(english:"Ubuntu 9.04 / 9.10 / 10.04 LTS : pcsc-lite vulnerability (USN-969-1)");
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
"It was discovered that the PC/SC service did not correctly handle
malformed messages. A local attacker could exploit this to execute
arbitrary code with root privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libpcsclite-dev, libpcsclite1 and / or pcscd
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcsclite-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcsclite1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pcscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(9\.04|9\.10|10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.04 / 9.10 / 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.04", pkgname:"libpcsclite-dev", pkgver:"1.4.102-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpcsclite1", pkgver:"1.4.102-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pcscd", pkgver:"1.4.102-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpcsclite-dev", pkgver:"1.5.3-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpcsclite1", pkgver:"1.5.3-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"pcscd", pkgver:"1.5.3-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpcsclite-dev", pkgver:"1.5.3-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpcsclite1", pkgver:"1.5.3-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"pcscd", pkgver:"1.5.3-1ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpcsclite-dev / libpcsclite1 / pcscd");
}
