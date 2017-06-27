#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1560-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62038);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/25 16:19:24 $");

  script_cve_id("CVE-2012-3442", "CVE-2012-3443", "CVE-2012-3444");
  script_bugtraq_id(54742);
  script_osvdb_id(84359, 84360, 84361);
  script_xref(name:"USN", value:"1560-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : python-django vulnerabilities (USN-1560-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Django incorrectly validated the scheme of a
redirect target. If a user were tricked into opening a specially
crafted URL, an attacker could possibly exploit this to conduct
cross-site scripting (XSS) attacks. (CVE-2012-3442)

It was discovered that Django incorrectly handled validating certain
images. A remote attacker could use this flaw to cause the server to
consume memory, leading to a denial of service. (CVE-2012-3443)

Jeroen Dekkers discovered that Django incorrectly handled certain
image dimensions. A remote attacker could use this flaw to cause the
server to consume resources, leading to a denial of service.
(CVE-2012-3444).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-django package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/11");
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
if (! ereg(pattern:"^(10\.04|11\.04|11\.10|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.04 / 11.10 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"python-django", pkgver:"1.1.1-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"python-django", pkgver:"1.2.5-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"python-django", pkgver:"1.3-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python-django", pkgver:"1.3.1-4ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-django");
}
