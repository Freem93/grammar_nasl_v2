#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2105-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72503);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/25 16:34:55 $");

  script_cve_id("CVE-2013-1069", "CVE-2013-1070");
  script_bugtraq_id(65569, 65575);
  script_osvdb_id(103348, 103349);
  script_xref(name:"USN", value:"2105-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.10 : maas vulnerabilities (USN-2105-1)");
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
"James Troup discovered that MAAS stored RabbitMQ authentication
credentials in a world-readable file. A local authenticated user could
read this password and potentially gain privileges of other user
accounts. This update restricts the file permissions to prevent
unintended access. (CVE-2013-1069)

Chris Glass discovered that the MAAS API was vulnerable to cross-site
scripting vulnerabilities. With cross-site scripting vulnerabilities,
if a user were tricked into viewing a specially crafted page, a remote
attacker could exploit this to modify the contents, or steal
confidential data, within the same domain. (CVE-2013-1070).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected maas-region-controller and / or python-django-maas
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:maas-region-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-django-maas");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/14");
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
if (! ereg(pattern:"^(12\.04|12\.10|13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10 / 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"maas-region-controller", pkgver:"1.2+bzr1373+dfsg-0ubuntu1~12.04.5")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python-django-maas", pkgver:"1.2+bzr1373+dfsg-0ubuntu1~12.04.5")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"maas-region-controller", pkgver:"1.2+bzr1373+dfsg-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"python-django-maas", pkgver:"1.2+bzr1373+dfsg-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"maas-region-controller", pkgver:"1.4+bzr1693+dfsg-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"python-django-maas", pkgver:"1.4+bzr1693+dfsg-0ubuntu2.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "maas-region-controller / python-django-maas");
}
