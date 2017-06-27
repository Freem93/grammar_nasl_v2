#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1481-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59603);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/25 16:19:24 $");

  script_cve_id("CVE-2012-0781", "CVE-2012-1172", "CVE-2012-2143", "CVE-2012-2317", "CVE-2012-2335", "CVE-2012-2336", "CVE-2012-2386");
  script_bugtraq_id(47545, 51992, 53388, 53403, 53729, 54875);
  script_osvdb_id(72399, 78571, 81633, 81791, 82213, 82509, 82510, 82577, 82578, 83111);
  script_xref(name:"USN", value:"1481-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : php5 vulnerabilities (USN-1481-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that PHP incorrectly handled certain Tidy::diagnose
operations on invalid objects. A remote attacker could use this flaw
to cause PHP to crash, leading to a denial of service. (CVE-2012-0781)

It was discovered that PHP incorrectly handled certain multi-file
upload filenames. A remote attacker could use this flaw to cause a
denial of service, or to perform a directory traversal attack.
(CVE-2012-1172)

Rubin Xu and Joseph Bonneau discovered that PHP incorrectly handled
certain Unicode characters in passwords passed to the crypt()
function. A remote attacker could possibly use this flaw to bypass
authentication. (CVE-2012-2143)

It was discovered that a Debian/Ubuntu specific patch caused PHP to
incorrectly handle empty salt strings. A remote attacker could
possibly use this flaw to bypass authentication. This issue only
affected Ubuntu 10.04 LTS and Ubuntu 11.04. (CVE-2012-2317)

It was discovered that PHP, when used as a stand alone CGI processor
for the Apache Web Server, did not properly parse and filter query
strings. This could allow a remote attacker to execute arbitrary code
running with the privilege of the web server, or to perform a denial
of service. Configurations using mod_php5 and FastCGI were not
vulnerable. (CVE-2012-2335, CVE-2012-2336)

Alexander Gavrun discovered that the PHP Phar extension incorrectly
handled certain malformed TAR files. A remote attacker could use this
flaw to perform a denial of service, or possibly execute arbitrary
code. (CVE-2012-2386).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php5 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP CGI Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/20");
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

if (ubuntu_check(osver:"8.04", pkgname:"php5", pkgver:"5.2.4-2ubuntu5.25")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5", pkgver:"5.3.2-1ubuntu4.17")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"php5", pkgver:"5.3.5-1ubuntu7.10")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"php5", pkgver:"5.3.6-13ubuntu3.8")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"php5", pkgver:"5.3.10-1ubuntu3.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php5");
}
