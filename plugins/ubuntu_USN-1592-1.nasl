#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1592-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62410);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/25 16:19:25 $");

  script_cve_id("CVE-2011-1521", "CVE-2011-4940", "CVE-2011-4944", "CVE-2012-0845", "CVE-2012-1150");
  script_bugtraq_id(47024, 51239, 51996, 52732, 54083);
  script_osvdb_id(71330, 79249, 80009, 82462, 83057);
  script_xref(name:"USN", value:"1592-1");

  script_name(english:"Ubuntu 11.04 / 11.10 : python2.7 vulnerabilities (USN-1592-1)");
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
"Niels Heinen discovered that the urllib and urllib2 modules would
process Location headers that specify a redirection to file: URLs. A
remote attacker could exploit this to obtain sensitive information or
cause a denial of service. This issue only affected Ubuntu 11.04.
(CVE-2011-1521)

It was discovered that SimpleHTTPServer did not use a charset
parameter in the Content-Type HTTP header. An attacker could
potentially exploit this to conduct cross-site scripting (XSS) attacks
against Internet Explorer 7 users. This issue only affected Ubuntu
11.04. (CVE-2011-4940)

It was discovered that Python distutils contained a race condition
when creating the ~/.pypirc file. A local attacker could exploit this
to obtain sensitive information. (CVE-2011-4944)

It was discovered that SimpleXMLRPCServer did not properly validate
its input when handling HTTP POST requests. A remote attacker could
exploit this to cause a denial of service via excessive CPU
utilization. (CVE-2012-0845)

It was discovered that Python was susceptible to hash algorithm
attacks. An attacker could cause a denial of service under certian
circumstances. This update adds the '-R' command line option and
honors setting the PYTHONHASHSEED environment variable to 'random' to
salt str and datetime objects with an unpredictable value.
(CVE-2012-1150).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python2.7 and / or python2.7-minimal packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/03");
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
if (! ereg(pattern:"^(11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"11.04", pkgname:"python2.7", pkgver:"2.7.1-5ubuntu2.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"python2.7-minimal", pkgver:"2.7.1-5ubuntu2.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"python2.7", pkgver:"2.7.2-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"python2.7-minimal", pkgver:"2.7.2-5ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2.7 / python2.7-minimal");
}
