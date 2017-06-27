#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-901-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44641);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:45:43 $");

  script_cve_id("CVE-2009-2855", "CVE-2010-0308");
  script_bugtraq_id(36091, 37522);
  script_osvdb_id(57193, 62044);
  script_xref(name:"USN", value:"901-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 / 9.10 : squid vulnerabilities (USN-901-1)");
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
"It was discovered that Squid incorrectly handled certain auth headers.
A remote attacker could exploit this with a specially crafted auth
header and cause Squid to go into an infinite loop, resulting in a
denial of service. This issue only affected Ubuntu 8.10, 9.04 and
9.10. (CVE-2009-2855)

It was discovered that Squid incorrectly handled certain DNS packets.
A remote attacker could exploit this with a specially crafted DNS
packet and cause Squid to crash, resulting in a denial of service.
(CVE-2010-0308).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squidclient");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"squid", pkgver:"2.5.12-4ubuntu2.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"squid-cgi", pkgver:"2.5.12-4ubuntu2.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"squid-common", pkgver:"2.5.12-4ubuntu2.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"squidclient", pkgver:"2.5.12-4ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"squid", pkgver:"2.6.18-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"squid-cgi", pkgver:"2.6.18-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"squid-common", pkgver:"2.6.18-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"squidclient", pkgver:"2.6.18-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"squid", pkgver:"2.7.STABLE3-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"squid-cgi", pkgver:"2.7.STABLE3-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"squid-common", pkgver:"2.7.STABLE3-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"squid", pkgver:"2.7.STABLE3-4.1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"squid-cgi", pkgver:"2.7.STABLE3-4.1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"squid-common", pkgver:"2.7.STABLE3-4.1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"squid", pkgver:"2.7.STABLE6-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"squid-cgi", pkgver:"2.7.STABLE6-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"squid-common", pkgver:"2.7.STABLE6-2ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid / squid-cgi / squid-common / squidclient");
}
