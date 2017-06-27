#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1070-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52164);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2011-0414");
  script_bugtraq_id(46491);
  script_osvdb_id(72539);
  script_xref(name:"USN", value:"1070-1");

  script_name(english:"Ubuntu 10.10 : bind9 vulnerability (USN-1070-1)");
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
"It was discovered that Bind incorrectly handled IXFR transfers and
dynamic updates while under heavy load when used as an authoritative
server. A remote attacker could use this flaw to cause Bind to stop
responding, resulting in a denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind9-60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns66");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblwres60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lwresd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.10", pkgname:"bind9", pkgver:"9.7.1.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"bind9-doc", pkgver:"9.7.1.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"bind9-host", pkgver:"9.7.1.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"bind9utils", pkgver:"9.7.1.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dnsutils", pkgver:"9.7.1.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"host", pkgver:"9.7.1.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libbind-dev", pkgver:"9.7.1.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libbind9-60", pkgver:"9.7.1.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libdns66", pkgver:"1:9.7.1.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libisc60", pkgver:"9.7.1.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libisccc60", pkgver:"9.7.1.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libisccfg60", pkgver:"9.7.1.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"liblwres60", pkgver:"9.7.1.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"lwresd", pkgver:"9.7.1.dfsg.P2-2ubuntu0.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind9 / bind9-doc / bind9-host / bind9utils / dnsutils / host / etc");
}
