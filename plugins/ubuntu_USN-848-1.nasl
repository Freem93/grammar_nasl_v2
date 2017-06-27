#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-848-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42146);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2009-0668", "CVE-2009-0669");
  script_bugtraq_id(35987);
  script_xref(name:"USN", value:"848-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : zope3 vulnerabilities (USN-848-1)");
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
"It was discovered that the Zope Object Database (ZODB) database server
(ZEO) improperly filtered certain commands when a database is shared
among multiple applications or application instances. A remote
attacker could send malicious commands to the server and execute
arbitrary code. (CVE-2009-0668)

It was discovered that the Zope Object Database (ZODB) database server
(ZEO) did not handle authentication properly when a database is shared
among multiple applications or application instances. A remote
attacker could use this flaw to bypass security restrictions.
(CVE-2009-0669)

It was discovered that Zope did not limit the number of new object ids
a client could request. A remote attacker could use this flaw to
consume a huge amount of resources, leading to a denial of service.
(No CVE identifier).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-zopeinterface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-zopeinterface-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-zopeinterface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:zope3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:zope3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:zope3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:zope3-sandbox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/15");
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

if (ubuntu_check(osver:"6.06", pkgname:"python-zopeinterface", pkgver:"3.2.1-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-zopeinterface", pkgver:"3.2.1-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"zope3", pkgver:"3.2.1-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"zope3-doc", pkgver:"3.2.1-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"zope3-sandbox", pkgver:"3.2.1-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-zopeinterface", pkgver:"3.3.1-5ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-zopeinterface-dbg", pkgver:"3.3.1-5ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"zope3", pkgver:"3.3.1-5ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"zope3-dbg", pkgver:"3.3.1-5ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"zope3-doc", pkgver:"3.3.1-5ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"zope3-sandbox", pkgver:"3.3.1-5ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-zopeinterface", pkgver:"3.3.1-7ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-zopeinterface-dbg", pkgver:"3.3.1-7ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"zope3", pkgver:"3.3.1-7ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"zope3-dbg", pkgver:"3.3.1-7ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"zope3-doc", pkgver:"3.3.1-7ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"zope3-sandbox", pkgver:"3.3.1-7ubuntu0.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-zopeinterface", pkgver:"3.4.0-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-zopeinterface-dbg", pkgver:"3.4.0-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"zope3", pkgver:"3.4.0-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"zope3-dbg", pkgver:"3.4.0-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"zope3-doc", pkgver:"3.4.0-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"zope3-sandbox", pkgver:"3.4.0-0ubuntu3.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-zopeinterface / python-zopeinterface-dbg / etc");
}
