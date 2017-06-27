#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-72-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20693);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/08/17 14:24:38 $");

  script_cve_id("CVE-2005-0155", "CVE-2005-0156");
  script_xref(name:"USN", value:"72-1");

  script_name(english:"Ubuntu 4.10 : perl vulnerabilities (USN-72-1)");
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
"Two exploitable vulnerabilities involving setuid-enabled perl scripts
have been discovered. The package 'perl-suid' provides a wrapper
around perl which allows to use setuid-root perl scripts, i.e.
user-callable Perl scripts which have full root privileges.

Previous versions allowed users to overwrite arbitrary files by
setting the PERLIO_DEBUG environment variable and calling an arbitrary
setuid-root perl script. The file that PERLIO_DEBUG points to was then
overwritten by Perl debug messages. This did not allow precise control
over the file content, but could destroy important data. PERLIO_DEBUG
is now ignored for setuid scripts. (CAN-2005-0155)

In addition, calling a setuid-root perl script with a very long path
caused a buffer overflow if PERLIO_DEBUG was set. This buffer overflow
could be exploited to execute arbitrary files with full root
privileges. (CAN-2005-0156).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcgi-fast-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libperl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libperl5.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl-suid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"libcgi-fast-perl", pkgver:"5.8.4-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libperl-dev", pkgver:"5.8.4-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libperl5.8", pkgver:"5.8.4-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"perl", pkgver:"5.8.4-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"perl-base", pkgver:"5.8.4-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"perl-debug", pkgver:"5.8.4-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"perl-doc", pkgver:"5.8.4-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"perl-modules", pkgver:"5.8.4-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"perl-suid", pkgver:"5.8.4-2ubuntu0.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcgi-fast-perl / libperl-dev / libperl5.8 / perl / perl-base / etc");
}
