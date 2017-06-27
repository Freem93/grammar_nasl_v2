#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1713-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64376);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/25 16:27:04 $");

  script_cve_id("CVE-2012-5643", "CVE-2013-0189");
  script_bugtraq_id(56957, 57646);
  script_xref(name:"USN", value:"1713-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.10 / 12.04 LTS / 12.10 : squid, squid3 vulnerabilities (USN-1713-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that squid's cachemgr.cgi was vulnerable to
excessive resource use. A remote attacker could exploit this flaw to
perform a denial of service attack on the server and other hosted
services. (CVE-2012-5643)

It was discovered that the patch for CVE-2012-5643 was incorrect. A
remote attacker could exploit this flaw to perform a denial of service
attack. (CVE-2013-0189).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squid-cgi package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-cgi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/31");
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
if (! ereg(pattern:"^(10\.04|11\.10|12\.04|12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.10 / 12.04 / 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"squid-cgi", pkgver:"2.7.STABLE7-1ubuntu12.6")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"squid-cgi", pkgver:"3.1.14-1ubuntu0.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"squid-cgi", pkgver:"3.1.19-1ubuntu3.12.04.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"squid-cgi", pkgver:"3.1.20-1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid-cgi");
}