#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-742-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37359);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-3520", "CVE-2008-3521", "CVE-2008-3522");
  script_bugtraq_id(31470);
  script_xref(name:"USN", value:"742-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : jasper vulnerabilities (USN-742-1)");
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
"It was discovered that JasPer did not correctly handle memory
allocation when parsing certain malformed JPEG2000 images. If a user
were tricked into opening a specially crafted image with an
application that uses libjasper, an attacker could cause a denial of
service and possibly execute arbitrary code with the user's
privileges. (CVE-2008-3520)

It was discovered that JasPer created temporary files in an insecure
way. Local users could exploit a race condition and cause a denial of
service in libjasper applications. (CVE-2008-3521)

It was discovered that JasPer did not correctly handle certain
formatting operations. If a user were tricked into opening a specially
crafted image with an application that uses libjasper, an attacker
could cause a denial of service and possibly execute arbitrary code
with the user's privileges. (CVE-2008-3522).

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
  script_cwe_id(59, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjasper-1.701-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjasper-1.701-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjasper-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjasper-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjasper1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/19");
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

if (ubuntu_check(osver:"6.06", pkgname:"libjasper-1.701-1", pkgver:"1.701.0-2ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libjasper-1.701-dev", pkgver:"1.701.0-2ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libjasper-runtime", pkgver:"1.701.0-2ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libjasper-dev", pkgver:"1.900.1-3ubuntu0.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libjasper-runtime", pkgver:"1.900.1-3ubuntu0.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libjasper1", pkgver:"1.900.1-3ubuntu0.7.10.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libjasper-dev", pkgver:"1.900.1-3ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libjasper-runtime", pkgver:"1.900.1-3ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libjasper1", pkgver:"1.900.1-3ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libjasper-dev", pkgver:"1.900.1-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libjasper-runtime", pkgver:"1.900.1-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libjasper1", pkgver:"1.900.1-5ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjasper-1.701-1 / libjasper-1.701-dev / libjasper-dev / etc");
}
