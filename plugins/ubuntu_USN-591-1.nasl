#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-591-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31678);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:29:19 $");

  script_cve_id("CVE-2007-4770", "CVE-2007-4771");
  script_bugtraq_id(27455);
  script_osvdb_id(41189, 41190);
  script_xref(name:"USN", value:"591-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : icu vulnerabilities (USN-591-1)");
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
"Will Drewry discovered that libicu did not properly handle '\0' when
processing regular expressions. If an application linked against
libicu processed a crafted regular expression, an attacker could
execute arbitrary code with privileges of the user invoking the
program. (CVE-2007-4770)

Will Drewry discovered that libicu did not properly limit its
backtracking stack size. If an application linked against libicu
processed a crafted regular expression, an attacker could cause a
denial of service via resource exhaustion. (CVE-2007-4771).

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
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icu-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libicu34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libicu34-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libicu36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libicu36-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/26");
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

if (ubuntu_check(osver:"6.06", pkgname:"icu-doc", pkgver:"3.4.1a-1ubuntu1.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libicu34", pkgver:"3.4.1a-1ubuntu1.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libicu34-dev", pkgver:"3.4.1a-1ubuntu1.6.06.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"icu-doc", pkgver:"3.4.1a-1ubuntu1.6.10.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libicu34", pkgver:"3.4.1a-1ubuntu1.6.10.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libicu34-dev", pkgver:"3.4.1a-1ubuntu1.6.10.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"icu-doc", pkgver:"3.6-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libicu36", pkgver:"3.6-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libicu36-dev", pkgver:"3.6-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"icu-doc", pkgver:"3.6-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libicu36", pkgver:"3.6-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libicu36-dev", pkgver:"3.6-3ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icu-doc / libicu34 / libicu34-dev / libicu36 / libicu36-dev");
}
