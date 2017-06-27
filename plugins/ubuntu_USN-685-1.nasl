#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-685-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38099);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-0960", "CVE-2008-2292", "CVE-2008-4309");
  script_bugtraq_id(29212, 29623, 32020);
  script_xref(name:"USN", value:"685-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : net-snmp vulnerabilities (USN-685-1)");
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
"Wes Hardaker discovered that the SNMP service did not correctly
validate HMAC authentication requests. An unauthenticated remote
attacker could send specially crafted SNMPv3 traffic with a valid
username and gain access to the user's views without a valid
authentication passphrase. (CVE-2008-0960)

John Kortink discovered that the Net-SNMP Perl module did not
correctly check the size of returned values. If a user or automated
system were tricked into querying a malicious SNMP server, the
application using the Perl module could be made to crash, leading to a
denial of service. This did not affect Ubuntu 8.10. (CVE-2008-2292)

It was discovered that the SNMP service did not correctly handle large
GETBULK requests. If an unauthenticated remote attacker sent a
specially crafted request, the SNMP service could be made to crash,
leading to a denial of service. (CVE-2008-4309).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 119, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:snmpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tkmib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.10|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.10 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libsnmp-base", pkgver:"5.2.1.2-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsnmp-perl", pkgver:"5.2.1.2-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsnmp9", pkgver:"5.2.1.2-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsnmp9-dev", pkgver:"5.2.1.2-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"snmp", pkgver:"5.2.1.2-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"snmpd", pkgver:"5.2.1.2-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"tkmib", pkgver:"5.2.1.2-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libsnmp-base", pkgver:"5.3.1-6ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libsnmp-dev", pkgver:"5.3.1-6ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libsnmp-perl", pkgver:"5.3.1-6ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libsnmp10", pkgver:"5.3.1-6ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"snmp", pkgver:"5.3.1-6ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"snmpd", pkgver:"5.3.1-6ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"tkmib", pkgver:"5.3.1-6ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsnmp-base", pkgver:"5.4.1~dfsg-4ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsnmp-dev", pkgver:"5.4.1~dfsg-4ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsnmp-perl", pkgver:"5.4.1~dfsg-4ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsnmp-python", pkgver:"5.4.1~dfsg-4ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsnmp15", pkgver:"5.4.1~dfsg-4ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"snmp", pkgver:"5.4.1~dfsg-4ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"snmpd", pkgver:"5.4.1~dfsg-4ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"tkmib", pkgver:"5.4.1~dfsg-4ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsnmp-base", pkgver:"5.4.1~dfsg-7.1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsnmp-dev", pkgver:"5.4.1~dfsg-7.1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsnmp-perl", pkgver:"5.4.1~dfsg-7.1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsnmp-python", pkgver:"5.4.1~dfsg-7.1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsnmp15", pkgver:"5.4.1~dfsg-7.1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"snmp", pkgver:"5.4.1~dfsg-7.1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"snmpd", pkgver:"5.4.1~dfsg-7.1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"tkmib", pkgver:"5.4.1~dfsg-7.1ubuntu6.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsnmp-base / libsnmp-dev / libsnmp-perl / libsnmp-python / etc");
}
