#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1765-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65607);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/25 16:27:05 $");

  script_cve_id("CVE-2012-3499", "CVE-2012-4557", "CVE-2012-4558", "CVE-2013-1048");
  script_osvdb_id(89275, 90556, 90557, 90852);
  script_xref(name:"USN", value:"1765-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 11.10 / 12.04 LTS / 12.10 : apache2 vulnerabilities (USN-1765-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Niels Heinen discovered that multiple modules incorrectly sanitized
certain strings, which could result in browsers becoming vulnerable to
cross-site scripting attacks when processing the output. With
cross-site scripting vulnerabilities, if a user were tricked into
viewing server output during a crafted server request, a remote
attacker could exploit this to modify the contents, or steal
confidential data (such as passwords), within the same domain.
(CVE-2012-3499, CVE-2012-4558)

It was discovered that the mod_proxy_ajp module incorrectly handled
error states. A remote attacker could use this issue to cause the
server to stop responding, resulting in a denial of service. This
issue only applied to Ubuntu 8.04 LTS, Ubuntu 10.04 LTS and Ubuntu
11.10. (CVE-2012-4557)

It was discovered that the apache2ctl script shipped in Ubuntu
packages incorrectly created the lock directory. A local attacker
could possibly use this issue to gain privileges. The symlink
protections in Ubuntu 11.10 and later should reduce this vulnerability
to a denial of service. (CVE-2013-1048).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2.2-common package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2.2-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/19");
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
if (! ereg(pattern:"^(8\.04|10\.04|11\.10|12\.04|12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 11.10 / 12.04 / 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"apache2.2-common", pkgver:"2.2.8-1ubuntu0.25")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apache2.2-common", pkgver:"2.2.14-5ubuntu8.11")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"apache2.2-common", pkgver:"2.2.20-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"apache2.2-common", pkgver:"2.2.22-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"apache2.2-common", pkgver:"2.2.22-6ubuntu2.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2.2-common");
}
