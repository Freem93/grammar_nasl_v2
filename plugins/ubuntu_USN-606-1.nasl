#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-606-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32186);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:29:19 $");

  script_cve_id("CVE-2008-1722");
  script_osvdb_id(44398);
  script_xref(name:"USN", value:"606-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 : cupsys vulnerability (USN-606-1)");
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
"Thomas Pollet discovered that CUPS did not properly validate the size
of PNG images. A local attacker, and a remote attacker if printer
sharing is enabled, could send a crafted file and cause a denial of
service or possibly execute arbitrary code as the non-root user in
Ubuntu 6.06 LTS and 7.04. In Ubuntu 7.10, attackers would be isolated
by the AppArmor CUPS profile. (CVE-2008-1722).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2-gnutls10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"cupsys", pkgver:"1.2.2-0ubuntu0.6.06.9")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"cupsys-bsd", pkgver:"1.2.2-0ubuntu0.6.06.9")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"cupsys-client", pkgver:"1.2.2-0ubuntu0.6.06.9")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsimage2", pkgver:"1.2.2-0ubuntu0.6.06.9")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsimage2-dev", pkgver:"1.2.2-0ubuntu0.6.06.9")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2", pkgver:"1.2.2-0ubuntu0.6.06.9")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2-dev", pkgver:"1.2.2-0ubuntu0.6.06.9")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2-gnutls10", pkgver:"1.2.2-0ubuntu0.6.06.9")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"cupsys", pkgver:"1.2.8-0ubuntu8.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"cupsys-bsd", pkgver:"1.2.8-0ubuntu8.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"cupsys-client", pkgver:"1.2.8-0ubuntu8.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"cupsys-common", pkgver:"1.2.8-0ubuntu8.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcupsimage2", pkgver:"1.2.8-0ubuntu8.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcupsimage2-dev", pkgver:"1.2.8-0ubuntu8.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcupsys2", pkgver:"1.2.8-0ubuntu8.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcupsys2-dev", pkgver:"1.2.8-0ubuntu8.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys", pkgver:"1.3.2-1ubuntu7.7")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys-bsd", pkgver:"1.3.2-1ubuntu7.7")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys-client", pkgver:"1.3.2-1ubuntu7.7")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys-common", pkgver:"1.3.2-1ubuntu7.7")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsimage2", pkgver:"1.3.2-1ubuntu7.7")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsimage2-dev", pkgver:"1.3.2-1ubuntu7.7")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsys2", pkgver:"1.3.2-1ubuntu7.7")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsys2-dev", pkgver:"1.3.2-1ubuntu7.7")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cupsys / cupsys-bsd / cupsys-client / cupsys-common / libcupsimage2 / etc");
}
