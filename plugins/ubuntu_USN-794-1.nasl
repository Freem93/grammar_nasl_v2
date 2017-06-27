#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-794-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39600);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:37:19 $");

  script_cve_id("CVE-2009-1391");
  script_bugtraq_id(35307);
  script_xref(name:"USN", value:"794-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 : libcompress-raw-zlib-perl, perl vulnerability (USN-794-1)");
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
"It was discovered that the Compress::Raw::Zlib Perl module incorrectly
handled certain zlib compressed streams. If a user or automated system
were tricked into processing a specially crafted compressed stream or
file, a remote attacker could crash the application, leading to a
denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcgi-fast-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcompress-raw-zlib-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libperl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libperl5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl-suid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/03");
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

if (ubuntu_check(osver:"8.04", pkgname:"libcompress-raw-zlib-perl", pkgver:"2.008-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcgi-fast-perl", pkgver:"5.10.0-11.1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcompress-raw-zlib-perl", pkgver:"2.011-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libperl-dev", pkgver:"5.10.0-11.1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libperl5.10", pkgver:"5.10.0-11.1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"perl", pkgver:"5.10.0-11.1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"perl-base", pkgver:"5.10.0-11.1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"perl-debug", pkgver:"5.10.0-11.1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"perl-doc", pkgver:"5.10.0-11.1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"perl-modules", pkgver:"5.10.0-11.1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"perl-suid", pkgver:"5.10.0-11.1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libcgi-fast-perl", pkgver:"5.10.0-19ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libcompress-raw-zlib-perl", pkgver:"2.015-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libperl-dev", pkgver:"5.10.0-19ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libperl5.10", pkgver:"5.10.0-19ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"perl", pkgver:"5.10.0-19ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"perl-base", pkgver:"5.10.0-19ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"perl-debug", pkgver:"5.10.0-19ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"perl-doc", pkgver:"5.10.0-19ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"perl-modules", pkgver:"5.10.0-19ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"perl-suid", pkgver:"5.10.0-19ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcgi-fast-perl / libcompress-raw-zlib-perl / libperl-dev / etc");
}
