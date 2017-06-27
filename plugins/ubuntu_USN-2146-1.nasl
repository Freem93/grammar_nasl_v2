#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2146-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73016);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/24 17:29:02 $");

  script_cve_id("CVE-2014-0106");
  script_bugtraq_id(65997);
  script_xref(name:"USN", value:"2146-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 12.10 / 13.10 : sudo vulnerabilities (USN-2146-1)");
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
"Sebastien Macke discovered that Sudo incorrectly handled blacklisted
environment variables when the env_reset option was disabled. A local
attacker could use this issue to possibly run unintended commands by
using blacklisted environment variables. In a default Ubuntu
installation, the env_reset option is enabled by default. This issue
only affected Ubuntu 10.04 LTS and Ubuntu 12.04 LTS. (CVE-2014-0106)

It was discovered that the Sudo init script set a date in the past on
existing timestamp files instead of using epoch to invalidate them
completely. A local attacker could possibly modify the system time to
attempt to reuse timestamp files. This issue only applied to Ubuntu
12.04 LTS, Ubuntu 12.10 and Ubuntu 13.10. (LP: #1223297).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sudo and / or sudo-ldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sudo-ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/14");
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
if (! ereg(pattern:"^(10\.04|12\.04|12\.10|13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 12.10 / 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"sudo", pkgver:"1.7.2p1-1ubuntu5.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"sudo-ldap", pkgver:"1.7.2p1-1ubuntu5.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"sudo", pkgver:"1.8.3p1-1ubuntu3.6")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"sudo-ldap", pkgver:"1.8.3p1-1ubuntu3.6")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"sudo", pkgver:"1.8.5p2-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"sudo-ldap", pkgver:"1.8.5p2-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"sudo", pkgver:"1.8.6p3-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"sudo-ldap", pkgver:"1.8.6p3-0ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo / sudo-ldap");
}
