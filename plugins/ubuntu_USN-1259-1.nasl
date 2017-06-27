#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1259-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56778);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/25 16:11:44 $");

  script_cve_id("CVE-2011-1176", "CVE-2011-3348", "CVE-2011-3368");
  script_bugtraq_id(46953, 49616, 49957);
  script_osvdb_id(74262, 74721, 75647, 76079);
  script_xref(name:"USN", value:"1259-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 / 11.10 : apache2, apache2-mpm-itk vulnerabilities (USN-1259-1)");
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
"It was discovered that the mod_proxy module in Apache did not properly
interact with the RewriteRule and ProxyPassMatch pattern matches in
the configuration of a reverse proxy. This could allow remote
attackers to contact internal webservers behind the proxy that were
not intended for external exposure. (CVE-2011-3368)

Stefano Nichele discovered that the mod_proxy_ajp module in Apache
when used with mod_proxy_balancer in certain configurations could
allow remote attackers to cause a denial of service via a malformed
HTTP request. (CVE-2011-3348)

Samuel Montosa discovered that the ITK Multi-Processing Module for
Apache did not properly handle certain configuration sections that
specify NiceValue but not AssignUserID, preventing Apache from
dropping privileges correctly. This issue only affected Ubuntu 10.04
LTS, Ubuntu 10.10 and Ubuntu 11.04. (CVE-2011-1176)

USN 1199-1 fixed a vulnerability in the byterange filter of Apache.
The upstream patch introduced a regression in Apache when handling
specific byte range requests. This update fixes the issue.

A flaw was discovered in the byterange filter in Apache. A remote
attacker could exploit this to cause a denial of service via resource
exhaustion.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected apache2-mpm-itk, apache2.2-bin and / or
apache2.2-common packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2.2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2.2-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/11");
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
if (! ereg(pattern:"^(8\.04|10\.04|10\.10|11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 10.10 / 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"apache2.2-common", pkgver:"2.2.8-1ubuntu0.22")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apache2-mpm-itk", pkgver:"2.2.14-5ubuntu8.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apache2.2-bin", pkgver:"2.2.14-5ubuntu8.7")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"apache2-mpm-itk", pkgver:"2.2.16-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"apache2.2-bin", pkgver:"2.2.16-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"apache2-mpm-itk", pkgver:"2.2.17-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"apache2.2-bin", pkgver:"2.2.17-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"apache2.2-bin", pkgver:"2.2.20-1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2-mpm-itk / apache2.2-bin / apache2.2-common");
}
