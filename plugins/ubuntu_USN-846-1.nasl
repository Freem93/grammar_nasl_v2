#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-846-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42081);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/07/06 14:12:42 $");

  script_cve_id("CVE-2009-0153");
  script_osvdb_id(54447);
  script_xref(name:"USN", value:"846-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 : icu vulnerability (USN-846-1)");
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
"It was discovered that ICU did not properly handle invalid byte
sequences during Unicode conversion. If an application using ICU
processed crafted data, content security mechanisms could be bypassed,
potentially leading to cross-site scripting (XSS) attacks.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icu-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32icu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lib32icu38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libicu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libicu38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libicu38-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/09");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"icu-doc", pkgver:"3.8-6ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"lib32icu-dev", pkgver:"3.8-6ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"lib32icu38", pkgver:"3.8-6ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libicu-dev", pkgver:"3.8-6ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libicu38", pkgver:"3.8-6ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libicu38-dbg", pkgver:"3.8-6ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"icu-doc", pkgver:"3.8.1-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"lib32icu-dev", pkgver:"3.8.1-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"lib32icu38", pkgver:"3.8.1-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libicu-dev", pkgver:"3.8.1-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libicu38", pkgver:"3.8.1-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libicu38-dbg", pkgver:"3.8.1-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"icu-doc", pkgver:"3.8.1-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"lib32icu-dev", pkgver:"3.8.1-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"lib32icu38", pkgver:"3.8.1-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libicu-dev", pkgver:"3.8.1-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libicu38", pkgver:"3.8.1-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libicu38-dbg", pkgver:"3.8.1-3ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icu-doc / lib32icu-dev / lib32icu38 / libicu-dev / libicu38 / etc");
}
