#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-447-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28044);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:29:17 $");

  script_cve_id("CVE-2007-1308", "CVE-2007-1564", "CVE-2007-1565");
  script_osvdb_id(34084, 35199);
  script_xref(name:"USN", value:"447-1");

  script_name(english:"Ubuntu 5.10 / 6.06 LTS / 6.10 : kdelibs vulnerabilities (USN-447-1)");
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
"It was discovered that Konqueror did not correctly handle iframes from
JavaScript. If a user were tricked into visiting a malicious website,
Konqueror could crash, resulting in a denial of service.
(CVE-2007-1308)

A flaw was discovered in how Konqueror handled PASV FTP responses. If
a user were tricked into visiting a malicious FTP server, a remote
attacker could perform a port-scan of machines within the user's
network, leading to private information disclosure. (CVE-2007-1564).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs4c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs4c2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs4c2a");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.10|6\.06|6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.10 / 6.06 / 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.10", pkgname:"kdelibs", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdelibs-bin", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdelibs-data", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdelibs4-dev", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdelibs4-doc", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdelibs4c2", pkgver:"4:3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdelibs4c2-dbg", pkgver:"3.4.3-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdelibs", pkgver:"3.5.2-0ubuntu18.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdelibs-bin", pkgver:"3.5.2-0ubuntu18.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdelibs-data", pkgver:"3.5.2-0ubuntu18.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdelibs-dbg", pkgver:"3.5.2-0ubuntu18.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdelibs4-dev", pkgver:"3.5.2-0ubuntu18.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdelibs4-doc", pkgver:"3.5.2-0ubuntu18.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdelibs4c2a", pkgver:"4:3.5.2-0ubuntu18.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kdelibs", pkgver:"3.5.5-0ubuntu3.1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kdelibs-data", pkgver:"3.5.5-0ubuntu3.1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kdelibs-dbg", pkgver:"3.5.5-0ubuntu3.1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kdelibs4-dev", pkgver:"3.5.5-0ubuntu3.1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kdelibs4-doc", pkgver:"3.5.5-0ubuntu3.1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kdelibs4c2a", pkgver:"4:3.5.5-0ubuntu3.1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs / kdelibs-bin / kdelibs-data / kdelibs-dbg / kdelibs4-dev / etc");
}
