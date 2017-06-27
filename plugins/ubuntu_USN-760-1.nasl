#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-760-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37978);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:37:18 $");

  script_cve_id("CVE-2009-0163");
  script_osvdb_id(54462);
  script_xref(name:"USN", value:"760-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : cups, cupsys vulnerability (USN-760-1)");
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
"It was discovered that CUPS did not properly check the height of TIFF
images. If a user or automated system were tricked into opening a
crafted TIFF image file, a remote attacker could cause a denial of
service or possibly execute arbitrary code with user privileges. In
Ubuntu 7.10, 8.04 LTS, and 8.10, attackers would be isolated by the
AppArmor CUPS profile.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcups2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2-gnutls10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (! ereg(pattern:"^(6\.06|7\.10|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.10 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"cupsys", pkgver:"1.2.2-0ubuntu0.6.06.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"cupsys-bsd", pkgver:"1.2.2-0ubuntu0.6.06.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"cupsys-client", pkgver:"1.2.2-0ubuntu0.6.06.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsimage2", pkgver:"1.2.2-0ubuntu0.6.06.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsimage2-dev", pkgver:"1.2.2-0ubuntu0.6.06.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2", pkgver:"1.2.2-0ubuntu0.6.06.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2-dev", pkgver:"1.2.2-0ubuntu0.6.06.13")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2-gnutls10", pkgver:"1.2.2-0ubuntu0.6.06.13")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys", pkgver:"1.3.2-1ubuntu7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys-bsd", pkgver:"1.3.2-1ubuntu7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys-client", pkgver:"1.3.2-1ubuntu7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys-common", pkgver:"1.3.2-1ubuntu7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsimage2", pkgver:"1.3.2-1ubuntu7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsimage2-dev", pkgver:"1.3.2-1ubuntu7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsys2", pkgver:"1.3.2-1ubuntu7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsys2-dev", pkgver:"1.3.2-1ubuntu7.10")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"cupsys", pkgver:"1.3.7-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"cupsys-bsd", pkgver:"1.3.7-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"cupsys-client", pkgver:"1.3.7-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"cupsys-common", pkgver:"1.3.7-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libcupsimage2", pkgver:"1.3.7-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libcupsimage2-dev", pkgver:"1.3.7-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libcupsys2", pkgver:"1.3.7-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libcupsys2-dev", pkgver:"1.3.7-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cups", pkgver:"1.3.9-2ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cups-bsd", pkgver:"1.3.9-2ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cups-client", pkgver:"1.3.9-2ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cups-common", pkgver:"1.3.9-2ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cups-dbg", pkgver:"1.3.9-2ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cupsys", pkgver:"1.3.9-2ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cupsys-bsd", pkgver:"1.3.9-2ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cupsys-client", pkgver:"1.3.9-2ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cupsys-common", pkgver:"1.3.9-2ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cupsys-dbg", pkgver:"1.3.9-2ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcups2", pkgver:"1.3.9-2ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcups2-dev", pkgver:"1.3.9-2ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcupsimage2", pkgver:"1.3.9-2ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcupsimage2-dev", pkgver:"1.3.9-2ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcupsys2", pkgver:"1.3.9-2ubuntu9.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcupsys2-dev", pkgver:"1.3.9-2ubuntu9.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-bsd / cups-client / cups-common / cups-dbg / cupsys / etc");
}
