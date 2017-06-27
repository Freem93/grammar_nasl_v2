#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-906-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44985);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 21:21:53 $");

  script_cve_id("CVE-2009-3553", "CVE-2010-0302", "CVE-2010-0393");
  script_bugtraq_id(38510);
  script_osvdb_id(60204, 62715);
  script_xref(name:"USN", value:"906-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 / 9.10 : cups, cupsys vulnerabilities (USN-906-1)");
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
"It was discovered that the CUPS scheduler did not properly handle
certain network operations. A remote attacker could exploit this flaw
and cause the CUPS server to crash, resulting in a denial of service.
This issue only affected Ubuntu 8.04 LTS, 8.10, 9.04 and 9.10.
(CVE-2009-3553, CVE-2010-0302)

Ronald Volgers discovered that the CUPS lppasswd tool could be made to
load localized message strings from arbitrary files by setting an
environment variable. A local attacker could exploit this with a
format-string vulnerability leading to a root privilege escalation.
The default compiler options for Ubuntu 8.10, 9.04 and 9.10 should
reduce this vulnerability to a denial of service. (CVE-2010-0393).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cups-ppdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsddk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcups2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupscgi1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupscgi1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsdriver1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsdriver1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsmime1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsmime1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsppdc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsppdc1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2-gnutls10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/04");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"cupsys", pkgver:"1.2.2-0ubuntu0.6.06.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"cupsys-bsd", pkgver:"1.2.2-0ubuntu0.6.06.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"cupsys-client", pkgver:"1.2.2-0ubuntu0.6.06.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsimage2", pkgver:"1.2.2-0ubuntu0.6.06.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsimage2-dev", pkgver:"1.2.2-0ubuntu0.6.06.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2", pkgver:"1.2.2-0ubuntu0.6.06.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2-dev", pkgver:"1.2.2-0ubuntu0.6.06.17")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2-gnutls10", pkgver:"1.2.2-0ubuntu0.6.06.17")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"cupsys", pkgver:"1.3.7-1ubuntu3.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"cupsys-bsd", pkgver:"1.3.7-1ubuntu3.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"cupsys-client", pkgver:"1.3.7-1ubuntu3.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"cupsys-common", pkgver:"1.3.7-1ubuntu3.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libcupsimage2", pkgver:"1.3.7-1ubuntu3.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libcupsimage2-dev", pkgver:"1.3.7-1ubuntu3.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libcupsys2", pkgver:"1.3.7-1ubuntu3.8")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libcupsys2-dev", pkgver:"1.3.7-1ubuntu3.8")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cups", pkgver:"1.3.9-2ubuntu9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cups-bsd", pkgver:"1.3.9-2ubuntu9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cups-client", pkgver:"1.3.9-2ubuntu9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cups-common", pkgver:"1.3.9-2ubuntu9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cups-dbg", pkgver:"1.3.9-2ubuntu9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cupsys", pkgver:"1.3.9-2ubuntu9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cupsys-bsd", pkgver:"1.3.9-2ubuntu9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cupsys-client", pkgver:"1.3.9-2ubuntu9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cupsys-common", pkgver:"1.3.9-2ubuntu9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cupsys-dbg", pkgver:"1.3.9-2ubuntu9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcups2", pkgver:"1.3.9-2ubuntu9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcups2-dev", pkgver:"1.3.9-2ubuntu9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcupsimage2", pkgver:"1.3.9-2ubuntu9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcupsimage2-dev", pkgver:"1.3.9-2ubuntu9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcupsys2", pkgver:"1.3.9-2ubuntu9.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcupsys2-dev", pkgver:"1.3.9-2ubuntu9.5")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"cups", pkgver:"1.3.9-17ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"cups-bsd", pkgver:"1.3.9-17ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"cups-client", pkgver:"1.3.9-17ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"cups-common", pkgver:"1.3.9-17ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"cups-dbg", pkgver:"1.3.9-17ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"cupsys", pkgver:"1.3.9-17ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"cupsys-bsd", pkgver:"1.3.9-17ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"cupsys-client", pkgver:"1.3.9-17ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"cupsys-common", pkgver:"1.3.9-17ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"cupsys-dbg", pkgver:"1.3.9-17ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libcups2", pkgver:"1.3.9-17ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libcups2-dev", pkgver:"1.3.9-17ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libcupsimage2", pkgver:"1.3.9-17ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libcupsimage2-dev", pkgver:"1.3.9-17ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libcupsys2", pkgver:"1.3.9-17ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libcupsys2-dev", pkgver:"1.3.9-17ubuntu3.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"cups", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"cups-bsd", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"cups-client", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"cups-common", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"cups-dbg", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"cups-ppdc", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"cupsddk", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"cupsys", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"cupsys-bsd", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"cupsys-client", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"cupsys-common", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"cupsys-dbg", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libcups2", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libcups2-dev", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libcupscgi1", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libcupscgi1-dev", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libcupsdriver1", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libcupsdriver1-dev", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libcupsimage2", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libcupsimage2-dev", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libcupsmime1", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libcupsmime1-dev", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libcupsppdc1", pkgver:"1.4.1-5ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libcupsppdc1-dev", pkgver:"1.4.1-5ubuntu2.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-bsd / cups-client / cups-common / cups-dbg / cups-ppdc / etc");
}
