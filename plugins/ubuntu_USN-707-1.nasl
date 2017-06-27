#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-707-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38132);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-5183", "CVE-2008-5184", "CVE-2008-5286", "CVE-2008-5377");
  script_bugtraq_id(32419, 32518);
  script_xref(name:"USN", value:"707-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : cups, cupsys vulnerabilities (USN-707-1)");
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
"It was discovered that CUPS didn't properly handle adding a large
number of RSS subscriptions. A local user could exploit this and cause
CUPS to crash, leading to a denial of service. This issue only applied
to Ubuntu 7.10, 8.04 LTS and 8.10. (CVE-2008-5183)

It was discovered that CUPS did not authenticate users when adding and
cancelling RSS subscriptions. An unprivileged local user could bypass
intended restrictions and add a large number of RSS subscriptions.
This issue only applied to Ubuntu 7.10 and 8.04 LTS. (CVE-2008-5184)

It was discovered that the PNG filter in CUPS did not properly handle
certain malformed images. If a user or automated system were tricked
into opening a crafted PNG image file, a remote attacker could cause a
denial of service or execute arbitrary code with user privileges. In
Ubuntu 7.10, 8.04 LTS, and 8.10, attackers would be isolated by the
AppArmor CUPS profile. (CVE-2008-5286)

It was discovered that the example pstopdf CUPS filter created log
files in an insecure way. Local users could exploit a race condition
to create or overwrite files with the privileges of the user invoking
the program. This issue only applied to Ubuntu 6.06 LTS, 7.10, and
8.04 LTS. (CVE-2008-5377).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(59, 189, 255, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/12");
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

if (ubuntu_check(osver:"6.06", pkgname:"cupsys", pkgver:"1.2.2-0ubuntu0.6.06.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"cupsys-bsd", pkgver:"1.2.2-0ubuntu0.6.06.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"cupsys-client", pkgver:"1.2.2-0ubuntu0.6.06.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsimage2", pkgver:"1.2.2-0ubuntu0.6.06.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsimage2-dev", pkgver:"1.2.2-0ubuntu0.6.06.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2", pkgver:"1.2.2-0ubuntu0.6.06.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2-dev", pkgver:"1.2.2-0ubuntu0.6.06.12")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2-gnutls10", pkgver:"1.2.2-0ubuntu0.6.06.12")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys", pkgver:"1.3.2-1ubuntu7.9")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys-bsd", pkgver:"1.3.2-1ubuntu7.9")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys-client", pkgver:"1.3.2-1ubuntu7.9")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys-common", pkgver:"1.3.2-1ubuntu7.9")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsimage2", pkgver:"1.3.2-1ubuntu7.9")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsimage2-dev", pkgver:"1.3.2-1ubuntu7.9")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsys2", pkgver:"1.3.2-1ubuntu7.9")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsys2-dev", pkgver:"1.3.2-1ubuntu7.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"cupsys", pkgver:"1.3.7-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"cupsys-bsd", pkgver:"1.3.7-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"cupsys-client", pkgver:"1.3.7-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"cupsys-common", pkgver:"1.3.7-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libcupsimage2", pkgver:"1.3.7-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libcupsimage2-dev", pkgver:"1.3.7-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libcupsys2", pkgver:"1.3.7-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libcupsys2-dev", pkgver:"1.3.7-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cups", pkgver:"1.3.9-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cups-bsd", pkgver:"1.3.9-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cups-client", pkgver:"1.3.9-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cups-common", pkgver:"1.3.9-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cups-dbg", pkgver:"1.3.9-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cupsys", pkgver:"1.3.9-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cupsys-bsd", pkgver:"1.3.9-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cupsys-client", pkgver:"1.3.9-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cupsys-common", pkgver:"1.3.9-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cupsys-dbg", pkgver:"1.3.9-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcups2", pkgver:"1.3.9-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcups2-dev", pkgver:"1.3.9-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcupsimage2", pkgver:"1.3.9-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcupsimage2-dev", pkgver:"1.3.9-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcupsys2", pkgver:"1.3.9-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcupsys2-dev", pkgver:"1.3.9-2ubuntu6.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-bsd / cups-client / cups-common / cups-dbg / cupsys / etc");
}
