#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2995-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91558);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/01 21:07:49 $");

  script_cve_id("CVE-2016-3947", "CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4553", "CVE-2016-4554", "CVE-2016-4555", "CVE-2016-4556");
  script_osvdb_id(136596, 137402, 137403, 137404, 137405, 138132, 138133, 138134);
  script_xref(name:"USN", value:"2995-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 / 16.04 LTS : squid3 vulnerabilities (USN-2995-1)");
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
"Yuriy M. Kaminskiy discovered that the Squid pinger utility
incorrectly handled certain ICMPv6 packets. A remote attacker could
use this issue to cause Squid to crash, resulting in a denial of
service, or possibly cause Squid to leak information into log files.
(CVE-2016-3947)

Yuriy M. Kaminskiy discovered that the Squid cachemgr.cgi tool
incorrectly handled certain crafted data. A remote attacker could use
this issue to cause Squid to crash, resulting in a denial of service,
or possibly execute arbitrary code. (CVE-2016-4051)

It was discovered that Squid incorrectly handled certain Edge Side
Includes (ESI) responses. A remote attacker could possibly use this
issue to cause Squid to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2016-4052, CVE-2016-4053,
CVE-2016-4054)

Jianjun Chen discovered that Squid did not correctly ignore the Host
header when absolute-URI is provided. A remote attacker could possibly
use this issue to conduct cache-poisoning attacks. This issue only
affected Ubuntu 14.04 LTS, Ubuntu 15.10 and Ubuntu 16.04 LTS.
(CVE-2016-4553)

Jianjun Chen discovered that Squid incorrectly handled certain HTTP
Host headers. A remote attacker could possibly use this issue to
conduct cache-poisoning attacks. (CVE-2016-4554)

It was discovered that Squid incorrectly handled certain Edge Side
Includes (ESI) responses. A remote attacker could possibly use this
issue to cause Squid to crash, resulting in a denial of service.
(CVE-2016-4555, CVE-2016-4556).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squid-cgi and / or squid3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.10|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.10 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"squid-cgi", pkgver:"3.1.19-1ubuntu3.12.04.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"squid3", pkgver:"3.1.19-1ubuntu3.12.04.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"squid-cgi", pkgver:"3.3.8-1ubuntu6.8")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"squid3", pkgver:"3.3.8-1ubuntu6.8")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"squid-cgi", pkgver:"3.3.8-1ubuntu16.3")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"squid3", pkgver:"3.3.8-1ubuntu16.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"squid-cgi", pkgver:"3.5.12-1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"squid3", pkgver:"3.5.12-1ubuntu7.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid-cgi / squid3");
}
