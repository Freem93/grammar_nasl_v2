#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-803-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39800);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:37:19 $");

  script_cve_id("CVE-2009-0692");
  script_xref(name:"USN", value:"803-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : dhcp3 vulnerability (USN-803-1)");
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
"It was discovered that the DHCP client as included in dhcp3 did not
verify the length of certain option fields when processing a response
from an IPv4 dhcp server. If a user running Ubuntu 6.06 LTS or 8.04
LTS connected to a malicious dhcp server, a remote attacker could
cause a denial of service or execute arbitrary code as the user
invoking the program, typically the 'dhcp' user. For users running
Ubuntu 8.10 or 9.04, a remote attacker should only be able to cause a
denial of service in the DHCP client. In Ubuntu 9.04, attackers would
also be isolated by the AppArmor dhclient3 profile.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dhcp3-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dhcp3-client-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dhcp3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dhcp3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dhcp3-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dhcp3-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dhcp3-server-ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"dhcp3-client", pkgver:"3.0.3-6ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dhcp3-client-udeb", pkgver:"3.0.3-6ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dhcp3-common", pkgver:"3.0.3-6ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dhcp3-dev", pkgver:"3.0.3-6ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dhcp3-relay", pkgver:"3.0.3-6ubuntu7.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dhcp3-server", pkgver:"3.0.3-6ubuntu7.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dhcp3-client", pkgver:"3.0.6.dfsg-1ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dhcp3-client-udeb", pkgver:"3.0.6.dfsg-1ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dhcp3-common", pkgver:"3.0.6.dfsg-1ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dhcp3-dev", pkgver:"3.0.6.dfsg-1ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dhcp3-relay", pkgver:"3.0.6.dfsg-1ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dhcp3-server", pkgver:"3.0.6.dfsg-1ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"dhcp3-client", pkgver:"3.1.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"dhcp3-client-udeb", pkgver:"3.1.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"dhcp3-common", pkgver:"3.1.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"dhcp3-dev", pkgver:"3.1.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"dhcp3-relay", pkgver:"3.1.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"dhcp3-server", pkgver:"3.1.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"dhcp3-server-ldap", pkgver:"3.1.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dhcp-client", pkgver:"3.1.1-5ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dhcp3-client", pkgver:"3.1.1-5ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dhcp3-client-udeb", pkgver:"3.1.1-5ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dhcp3-common", pkgver:"3.1.1-5ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dhcp3-dev", pkgver:"3.1.1-5ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dhcp3-relay", pkgver:"3.1.1-5ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dhcp3-server", pkgver:"3.1.1-5ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dhcp3-server-ldap", pkgver:"3.1.1-5ubuntu8.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcp-client / dhcp3-client / dhcp3-client-udeb / dhcp3-common / etc");
}
