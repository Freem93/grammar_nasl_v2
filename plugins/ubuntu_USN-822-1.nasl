#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-822-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40767);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2009-0945", "CVE-2009-1687", "CVE-2009-1690", "CVE-2009-1698");
  script_bugtraq_id(34924, 35271, 35309, 35318);
  script_xref(name:"USN", value:"822-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 : kde4libs, kdelibs vulnerabilities (USN-822-1)");
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
"It was discovered that KDE-Libs did not properly handle certain
malformed SVG images. If a user were tricked into opening a specially
crafted SVG image, an attacker could cause a denial of service or
possibly execute arbitrary code with the privileges of the user
invoking the program. This issue only affected Ubuntu 9.04.
(CVE-2009-0945)

It was discovered that the KDE JavaScript garbage collector did not
properly handle memory allocation failures. If a user were tricked
into viewing a malicious website, an attacker could cause a denial of
service or possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2009-1687)

It was discovered that KDE-Libs did not properly handle HTML content
in the head element. If a user were tricked into viewing a malicious
website, an attacker could cause a denial of service or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2009-1690)

It was discovered that KDE-Libs did not properly handle the Cascading
Style Sheets (CSS) attr function call. If a user were tricked into
viewing a malicious website, an attacker could cause a denial of
service or possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2009-1698).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs4c2a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs5-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libplasma-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libplasma3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/25");
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

if (ubuntu_check(osver:"8.04", pkgname:"kdelibs", pkgver:"3.5.10-0ubuntu1~hardy1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdelibs-data", pkgver:"3.5.10-0ubuntu1~hardy1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdelibs-dbg", pkgver:"3.5.10-0ubuntu1~hardy1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdelibs4-dev", pkgver:"3.5.10-0ubuntu1~hardy1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdelibs4-doc", pkgver:"3.5.10-0ubuntu1~hardy1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdelibs4c2a", pkgver:"4:3.5.10-0ubuntu1~hardy1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs", pkgver:"3.5.10-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs-bin", pkgver:"4.1.4-0ubuntu1~intrepid1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs-data", pkgver:"3.5.10-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs-dbg", pkgver:"3.5.10-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs4-dev", pkgver:"3.5.10-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs4-doc", pkgver:"3.5.10-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs4c2a", pkgver:"4:3.5.10-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs5", pkgver:"4:4.1.4-0ubuntu1~intrepid1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs5-data", pkgver:"4.1.4-0ubuntu1~intrepid1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs5-dbg", pkgver:"4.1.4-0ubuntu1~intrepid1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs5-dev", pkgver:"4.1.4-0ubuntu1~intrepid1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs5-doc", pkgver:"4.1.4-0ubuntu1~intrepid1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdelibs", pkgver:"3.5.10.dfsg.1-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdelibs-bin", pkgver:"4.2.2-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdelibs-data", pkgver:"3.5.10.dfsg.1-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdelibs-dbg", pkgver:"3.5.10.dfsg.1-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdelibs4-dev", pkgver:"3.5.10.dfsg.1-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdelibs4c2a", pkgver:"4:3.5.10.dfsg.1-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdelibs5", pkgver:"4:4.2.2-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdelibs5-data", pkgver:"4.2.2-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdelibs5-dbg", pkgver:"4.2.2-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdelibs5-dev", pkgver:"4.2.2-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libplasma-dev", pkgver:"4.2.2-0ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libplasma3", pkgver:"4.2.2-0ubuntu5.1")) flag++;

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
