#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-808-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40417);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/27 14:37:19 $");

  script_cve_id("CVE-2009-0696");
  script_xref(name:"USN", value:"808-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : bind9 vulnerability (USN-808-1)");
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
"Micha Krause discovered that Bind did not correctly validate certain
dynamic DNS update packets. An unauthenticated remote attacker could
send specially crafted traffic to crash the DNS server, leading to a
denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind9-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind9-30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind9-40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns43");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns45");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc44");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc45");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblwres30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblwres40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblwres9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lwresd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"bind9", pkgver:"1:9.3.2-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"bind9-doc", pkgver:"9.3.2-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"bind9-host", pkgver:"9.3.2-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dnsutils", pkgver:"9.3.2-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libbind-dev", pkgver:"9.3.2-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libbind9-0", pkgver:"9.3.2-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdns21", pkgver:"9.3.2-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libisc11", pkgver:"9.3.2-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libisccc0", pkgver:"9.3.2-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libisccfg1", pkgver:"9.3.2-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"liblwres9", pkgver:"9.3.2-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"lwresd", pkgver:"9.3.2-2ubuntu1.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"bind9", pkgver:"1:9.4.2.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"bind9-doc", pkgver:"9.4.2.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"bind9-host", pkgver:"9.4.2.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"dnsutils", pkgver:"9.4.2.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libbind-dev", pkgver:"9.4.2.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libbind9-30", pkgver:"9.4.2.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libdns35", pkgver:"9.4.2.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libisc35", pkgver:"9.4.2.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libisccc30", pkgver:"9.4.2.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libisccfg30", pkgver:"9.4.2.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"liblwres30", pkgver:"9.4.2.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"lwresd", pkgver:"9.4.2.dfsg.P2-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"bind9", pkgver:"1:9.5.0.dfsg.P2-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"bind9-doc", pkgver:"9.5.0.dfsg.P2-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"bind9-host", pkgver:"9.5.0.dfsg.P2-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"bind9utils", pkgver:"9.5.0.dfsg.P2-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"dnsutils", pkgver:"9.5.0.dfsg.P2-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libbind-dev", pkgver:"9.5.0.dfsg.P2-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libbind9-40", pkgver:"9.5.0.dfsg.P2-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libdns43", pkgver:"9.5.0.dfsg.P2-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libisc44", pkgver:"9.5.0.dfsg.P2-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libisccc40", pkgver:"9.5.0.dfsg.P2-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libisccfg40", pkgver:"9.5.0.dfsg.P2-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"liblwres40", pkgver:"9.5.0.dfsg.P2-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"lwresd", pkgver:"9.5.0.dfsg.P2-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"bind9", pkgver:"1:9.5.1.dfsg.P2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"bind9-doc", pkgver:"9.5.1.dfsg.P2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"bind9-host", pkgver:"9.5.1.dfsg.P2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"bind9utils", pkgver:"9.5.1.dfsg.P2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"dnsutils", pkgver:"9.5.1.dfsg.P2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libbind-dev", pkgver:"9.5.1.dfsg.P2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libbind9-40", pkgver:"9.5.1.dfsg.P2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libdns45", pkgver:"9.5.1.dfsg.P2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libisc45", pkgver:"9.5.1.dfsg.P2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libisccc40", pkgver:"9.5.1.dfsg.P2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libisccfg40", pkgver:"9.5.1.dfsg.P2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"liblwres40", pkgver:"9.5.1.dfsg.P2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"lwresd", pkgver:"9.5.1.dfsg.P2-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind9 / bind9-doc / bind9-host / bind9utils / dnsutils / etc");
}
