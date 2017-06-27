#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-547-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28359);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2007-1659", "CVE-2007-1660", "CVE-2007-1661", "CVE-2007-1662", "CVE-2007-4766", "CVE-2007-4767", "CVE-2007-4768");
  script_osvdb_id(40759, 40760, 40766);
  script_xref(name:"USN", value:"547-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : pcre3 vulnerabilities (USN-547-1)");
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
"Tavis Ormandy and Will Drewry discovered multiple flaws in the regular
expression handling of PCRE. By tricking a user or service into
running specially crafted expressions via applications linked against
libpcre3, a remote attacker could crash the application, monopolize
CPU resources, or possibly execute arbitrary code with the
application's privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcre3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcre3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpcrecpp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pcregrep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pgrep");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"6.06", pkgname:"libpcre3", pkgver:"7.4-0ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpcre3-dev", pkgver:"7.4-0ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpcrecpp0", pkgver:"7.4-0ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"pcregrep", pkgver:"7.4-0ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"pgrep", pkgver:"7.4-0ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpcre3", pkgver:"7.4-0ubuntu0.6.10.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpcre3-dev", pkgver:"7.4-0ubuntu0.6.10.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpcrecpp0", pkgver:"7.4-0ubuntu0.6.10.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"pcregrep", pkgver:"7.4-0ubuntu0.6.10.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpcre3", pkgver:"7.4-0ubuntu0.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpcre3-dev", pkgver:"7.4-0ubuntu0.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpcrecpp0", pkgver:"7.4-0ubuntu0.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"pcregrep", pkgver:"7.4-0ubuntu0.7.04.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpcre3", pkgver:"7.4-0ubuntu0.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpcre3-dev", pkgver:"7.4-0ubuntu0.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpcrecpp0", pkgver:"7.4-0ubuntu0.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"pcregrep", pkgver:"7.4-0ubuntu0.7.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpcre3 / libpcre3-dev / libpcrecpp0 / pcregrep / pgrep");
}
