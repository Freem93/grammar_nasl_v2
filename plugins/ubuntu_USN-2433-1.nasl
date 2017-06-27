#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2433-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79741);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/03 13:42:51 $");

  script_cve_id("CVE-2014-8767", "CVE-2014-8768", "CVE-2014-8769", "CVE-2014-9140");
  script_bugtraq_id(71150, 71153, 71155, 71468);
  script_osvdb_id(114738, 114739, 114740, 115292);
  script_xref(name:"USN", value:"2433-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 14.04 LTS / 14.10 : tcpdump vulnerabilities (USN-2433-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Steffen Bauch discovered that tcpdump incorrectly handled printing
OSLR packets. A remote attacker could use this issue to cause tcpdump
to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2014-8767)

Steffen Bauch discovered that tcpdump incorrectly handled printing
GeoNet packets. A remote attacker could use this issue to cause
tcpdump to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only applied to Ubuntu 14.04 LTS
and Ubuntu 14.10. (CVE-2014-8768)

Steffen Bauch discovered that tcpdump incorrectly handled printing
AODV packets. A remote attacker could use this issue to cause tcpdump
to crash, resulting in a denial of service, reveal sensitive
information, or possibly execute arbitrary code. (CVE-2014-8769)

It was discovered that tcpdump incorrectly handled printing PPP
packets. A remote attacker could use this issue to cause tcpdump to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2014-9140)

In the default installation, attackers would be isolated by the
tcpdump AppArmor profile.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tcpdump package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2017 Canonical, Inc. / NASL script (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|12\.04|14\.04|14\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 14.04 / 14.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"tcpdump", pkgver:"4.0.0-6ubuntu3.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"tcpdump", pkgver:"4.2.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"tcpdump", pkgver:"4.5.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"tcpdump", pkgver:"4.6.2-1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tcpdump");
}
