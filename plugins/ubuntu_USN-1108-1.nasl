#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1108-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53372);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2011-0997");
  script_bugtraq_id(47176);
  script_xref(name:"USN", value:"1108-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : dhcp3 vulnerability (USN-1108-1)");
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
"Sebastian Krahmer discovered that the dhclient utility incorrectly
filtered crafted responses. An attacker could use this flaw with a
malicious DHCP server to execute arbitrary code, resulting in root
privilege escalation.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dhcp3-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dhcp3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dhcp3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dhcp3-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dhcp3-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dhcp3-server-ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"dhcp3-client", pkgver:"3.0.3-6ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dhcp3-common", pkgver:"3.0.3-6ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dhcp3-dev", pkgver:"3.0.3-6ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dhcp3-relay", pkgver:"3.0.3-6ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dhcp3-server", pkgver:"3.0.3-6ubuntu7.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dhcp3-client", pkgver:"3.0.6.dfsg-1ubuntu9.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dhcp3-common", pkgver:"3.0.6.dfsg-1ubuntu9.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dhcp3-dev", pkgver:"3.0.6.dfsg-1ubuntu9.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dhcp3-relay", pkgver:"3.0.6.dfsg-1ubuntu9.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dhcp3-server", pkgver:"3.0.6.dfsg-1ubuntu9.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"dhcp-client", pkgver:"3.1.2-1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"dhcp3-client", pkgver:"3.1.2-1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"dhcp3-common", pkgver:"3.1.2-1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"dhcp3-dev", pkgver:"3.1.2-1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"dhcp3-relay", pkgver:"3.1.2-1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"dhcp3-server", pkgver:"3.1.2-1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"dhcp3-server-ldap", pkgver:"3.1.2-1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dhcp-client", pkgver:"3.1.3-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dhcp3-client", pkgver:"3.1.3-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dhcp3-common", pkgver:"3.1.3-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dhcp3-dev", pkgver:"3.1.3-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dhcp3-relay", pkgver:"3.1.3-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dhcp3-server", pkgver:"3.1.3-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dhcp3-server-ldap", pkgver:"3.1.3-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dhcp-client", pkgver:"3.1.3-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dhcp3-client", pkgver:"3.1.3-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dhcp3-common", pkgver:"3.1.3-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dhcp3-dev", pkgver:"3.1.3-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dhcp3-relay", pkgver:"3.1.3-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dhcp3-server", pkgver:"3.1.3-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dhcp3-server-ldap", pkgver:"3.1.3-2ubuntu6.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcp-client / dhcp3-client / dhcp3-common / dhcp3-dev / dhcp3-relay / etc");
}
