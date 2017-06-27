#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1442-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59170);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/25 16:11:46 $");

  script_cve_id("CVE-2012-2337");
  script_osvdb_id(81982);
  script_xref(name:"USN", value:"1442-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : sudo vulnerability (USN-1442-1)");
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
"It was discovered that sudo incorrectly handled network masks when
using Host and Host_List. A local user who is listed in sudoers may be
allowed to run commands on unintended hosts when IPv4 network masks
are used to grant access. A local attacker could exploit this to
bypass intended access restrictions. Host and Host_List are not used
in the default installation of Ubuntu.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sudo and / or sudo-ldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sudo-ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2016 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|10\.04|11\.04|11\.10|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 11.04 / 11.10 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"sudo", pkgver:"1.6.9p10-1ubuntu3.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"sudo-ldap", pkgver:"1.6.9p10-1ubuntu3.9")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"sudo", pkgver:"1.7.2p1-1ubuntu5.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"sudo-ldap", pkgver:"1.7.2p1-1ubuntu5.4")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"sudo", pkgver:"1.7.4p4-5ubuntu7.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"sudo-ldap", pkgver:"1.7.4p4-5ubuntu7.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"sudo", pkgver:"1.7.4p6-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"sudo-ldap", pkgver:"1.7.4p6-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"sudo", pkgver:"1.8.3p1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"sudo-ldap", pkgver:"1.8.3p1-1ubuntu3.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo / sudo-ldap");
}
