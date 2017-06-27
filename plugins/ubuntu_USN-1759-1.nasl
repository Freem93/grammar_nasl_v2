#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1759-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65251);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/25 16:27:05 $");

  script_cve_id("CVE-2013-1640", "CVE-2013-1652", "CVE-2013-1653", "CVE-2013-1654", "CVE-2013-1655", "CVE-2013-2275");
  script_osvdb_id(91222, 91223, 91224, 91226, 91227, 91228);
  script_xref(name:"USN", value:"1759-1");

  script_name(english:"Ubuntu 11.10 / 12.04 LTS / 12.10 : puppet vulnerabilities (USN-1759-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Puppet agents incorrectly handled certain kick
connections in a non-default configuration. An attacker on an
authenticated client could use this issue to possibly execute
arbitrary code. (CVE-2013-1653)

It was discovered that Puppet incorrectly handled certain catalog
requests. An attacker on an authenticated client could use this issue
to possibly execute arbitrary code on the master. (CVE-2013-1640)

It was discovered that Puppet incorrectly handled certain client
requests. An attacker on an authenticated client could use this issue
to possibly perform unauthorized actions. (CVE-2013-1652)

It was discovered that Puppet incorrectly handled certain SSL
connections. An attacker could use this issue to possibly downgrade
connections to SSLv2. (CVE-2013-1654)

It was discovered that Puppet incorrectly handled serialized
attributes. An attacker on an authenticated client could use this
issue to possibly cause a denial of service, or execute arbitrary.
(CVE-2013-1655)

It was discovered that Puppet incorrectly handled submitted reports.
An attacker on an authenticated node could use this issue to possibly
submit a report for any other node. (CVE-2013-2275).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected puppet-common package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:puppet-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/13");
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
if (! ereg(pattern:"^(11\.10|12\.04|12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.10 / 12.04 / 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"11.10", pkgname:"puppet-common", pkgver:"2.7.1-1ubuntu3.8")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"puppet-common", pkgver:"2.7.11-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"puppet-common", pkgver:"2.7.18-1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "puppet-common");
}
