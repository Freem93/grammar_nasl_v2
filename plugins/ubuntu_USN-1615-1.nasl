#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1615-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62677);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/25 16:19:25 $");

  script_cve_id("CVE-2011-4944", "CVE-2012-0845", "CVE-2012-1150", "CVE-2012-2135");
  script_osvdb_id(79249, 80009, 82462, 84757);
  script_xref(name:"USN", value:"1615-1");

  script_name(english:"Ubuntu 11.04 / 11.10 / 12.04 LTS / 12.10 : python3.2 vulnerabilities (USN-1615-1)");
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
"It was discovered that Python distutils contained a race condition
when creating the ~/.pypirc file. A local attacker could exploit this
to obtain sensitive information. (CVE-2011-4944)

It was discovered that SimpleXMLRPCServer did not properly validate
its input when handling HTTP POST requests. A remote attacker could
exploit this to cause a denial of service via excessive CPU
utilization. This issue only affected Ubuntu 11.04 and 11.10.
(CVE-2012-0845)

It was discovered that Python was susceptible to hash algorithm
attacks. An attacker could cause a denial of service under certian
circumstances. This update adds the '-R' command line option and
honors setting the PYTHONHASHSEED environment variable to 'random' to
salt str and datetime objects with an unpredictable value. This issue
only affected Ubuntu 11.04 and 11.10. (CVE-2012-1150)

Serhiy Storchaka discovered that the UTF16 decoder in Python did not
properly reset internal variables after error handling. An attacker
could exploit this to cause a denial of service via memory corruption.
This issue did not affect Ubuntu 12.10. (CVE-2012-2135).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python3.2 and / or python3.2-minimal packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.2-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/24");
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
if (! ereg(pattern:"^(11\.04|11\.10|12\.04|12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.04 / 11.10 / 12.04 / 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"11.04", pkgname:"python3.2", pkgver:"3.2-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"python3.2-minimal", pkgver:"3.2-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"python3.2", pkgver:"3.2.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"python3.2-minimal", pkgver:"3.2.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python3.2", pkgver:"3.2.3-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python3.2-minimal", pkgver:"3.2.3-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"python3.2", pkgver:"3.2.3-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"python3.2-minimal", pkgver:"3.2.3-6ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3.2 / python3.2-minimal");
}
