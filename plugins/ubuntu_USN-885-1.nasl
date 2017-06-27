#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-885-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44039);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/01 21:21:53 $");

  script_cve_id("CVE-2009-1757", "CVE-2010-0012");
  script_osvdb_id(54401, 61601);
  script_xref(name:"USN", value:"885-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 / 9.10 : transmission vulnerabilities (USN-885-1)");
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
"It was discovered that the Transmission web interface was vulnerable
to cross-site request forgery (CSRF) attacks. If a user were tricked
into opening a specially crafted web page in a browser while
Transmission was running, an attacker could trigger commands in
Transmission. This issue affected Ubuntu 9.04. (CVE-2009-1757)

Dan Rosenberg discovered that Transmission did not properly perform
input validation when processing torrent files. If a user were tricked
into opening a crafted torrent file, an attacker could overwrite files
via directory traversal. (CVE-2010-0012).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(22, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:transmission");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:transmission-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:transmission-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:transmission-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:transmission-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:transmission-qt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/15");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"transmission", pkgver:"1.06-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"transmission-cli", pkgver:"1.06-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"transmission-common", pkgver:"1.06-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"transmission-gtk", pkgver:"1.06-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"transmission", pkgver:"1.34-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"transmission-cli", pkgver:"1.34-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"transmission-common", pkgver:"1.34-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"transmission-gtk", pkgver:"1.34-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"transmission", pkgver:"1.51-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"transmission-cli", pkgver:"1.51-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"transmission-common", pkgver:"1.51-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"transmission-daemon", pkgver:"1.51-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"transmission-gtk", pkgver:"1.51-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"transmission", pkgver:"1.75-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"transmission-cli", pkgver:"1.75-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"transmission-common", pkgver:"1.75-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"transmission-daemon", pkgver:"1.75-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"transmission-gtk", pkgver:"1.75-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"transmission-qt", pkgver:"1.75-0ubuntu2.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "transmission / transmission-cli / transmission-common / etc");
}
