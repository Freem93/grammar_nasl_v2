#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-563-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29919);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:29:18 $");

  script_cve_id("CVE-2007-5849", "CVE-2007-6358");
  script_bugtraq_id(26917);
  script_osvdb_id(40719, 42029);
  script_xref(name:"USN", value:"563-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : cupsys vulnerabilities (USN-563-1)");
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
"Wei Wang discovered that the SNMP discovery backend did not correctly
calculate the length of strings. If a user were tricked into scanning
for printers, a remote attacker could send a specially crafted packet
and possibly execute arbitrary code.

Elias Pipping discovered that temporary files were not handled safely
in certain situations when converting PDF to PS. A local attacker
could cause a denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/10");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"cupsys", pkgver:"1.2.2-0ubuntu0.6.06.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"cupsys-bsd", pkgver:"1.2.2-0ubuntu0.6.06.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"cupsys-client", pkgver:"1.2.2-0ubuntu0.6.06.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsimage2", pkgver:"1.2.2-0ubuntu0.6.06.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsimage2-dev", pkgver:"1.2.2-0ubuntu0.6.06.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2", pkgver:"1.2.2-0ubuntu0.6.06.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2-dev", pkgver:"1.2.2-0ubuntu0.6.06.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2-gnutls10", pkgver:"1.2.2-0ubuntu0.6.06.6")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"cupsys", pkgver:"1.2.4-2ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"cupsys-bsd", pkgver:"1.2.4-2ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"cupsys-client", pkgver:"1.2.4-2ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"cupsys-common", pkgver:"1.2.4-2ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcupsimage2", pkgver:"1.2.4-2ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcupsimage2-dev", pkgver:"1.2.4-2ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcupsys2", pkgver:"1.2.4-2ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcupsys2-dev", pkgver:"1.2.4-2ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"cupsys", pkgver:"1.2.8-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"cupsys-bsd", pkgver:"1.2.8-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"cupsys-client", pkgver:"1.2.8-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"cupsys-common", pkgver:"1.2.8-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcupsimage2", pkgver:"1.2.8-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcupsimage2-dev", pkgver:"1.2.8-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcupsys2", pkgver:"1.2.8-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcupsys2-dev", pkgver:"1.2.8-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys", pkgver:"1.3.2-1ubuntu7.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys-bsd", pkgver:"1.3.2-1ubuntu7.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys-client", pkgver:"1.3.2-1ubuntu7.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys-common", pkgver:"1.3.2-1ubuntu7.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsimage2", pkgver:"1.3.2-1ubuntu7.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsimage2-dev", pkgver:"1.3.2-1ubuntu7.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsys2", pkgver:"1.3.2-1ubuntu7.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsys2-dev", pkgver:"1.3.2-1ubuntu7.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cupsys / cupsys-bsd / cupsys-client / cupsys-common / libcupsimage2 / etc");
}
