#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-222-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20765);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2005-3962");
  script_xref(name:"USN", value:"222-2");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : perl vulnerability (USN-222-2)");
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
"USN-222-1 fixed a vulnerability in the Perl interpreter. It was
discovered that the version of USN-222-1 was not sufficient to handle
all possible cases of malformed input that could lead to arbitrary
code execution, so another update is necessary.

Original advisory :

Jack Louis of Dyad Security discovered that Perl did not sufficiently
check the explicit length argument in format strings. Specially
crafted format strings with overly large length arguments led to a
crash of the Perl interpreter or even to execution of arbitrary
attacker-defined code with the privileges of the user running the Perl
program.

However, this attack was only possible in insecure Perl
programs which use variables with user-defined values in
string interpolations without checking their validity.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/21");
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
if (! ereg(pattern:"^(4\.10|5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"libcgi-fast-perl", pkgver:"5.8.4-2ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libperl-dev", pkgver:"5.8.4-2ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libperl5.8", pkgver:"5.8.4-2ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"perl", pkgver:"5.8.4-2ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"perl-base", pkgver:"5.8.4-2ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"perl-debug", pkgver:"5.8.4-2ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"perl-doc", pkgver:"5.8.4-2ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"perl-modules", pkgver:"5.8.4-2ubuntu0.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"perl-suid", pkgver:"5.8.4-2ubuntu0.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libcgi-fast-perl", pkgver:"5.8.4-6ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libperl-dev", pkgver:"5.8.4-6ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libperl5.8", pkgver:"5.8.4-6ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"perl", pkgver:"5.8.4-6ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"perl-base", pkgver:"5.8.4-6ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"perl-debug", pkgver:"5.8.4-6ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"perl-doc", pkgver:"5.8.4-6ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"perl-modules", pkgver:"5.8.4-6ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"perl-suid", pkgver:"5.8.4-6ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libcgi-fast-perl", pkgver:"5.8.7-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libperl-dev", pkgver:"5.8.7-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libperl5.8", pkgver:"5.8.7-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"perl", pkgver:"5.8.7-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"perl-base", pkgver:"5.8.7-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"perl-debug", pkgver:"5.8.7-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"perl-doc", pkgver:"5.8.7-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"perl-modules", pkgver:"5.8.7-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"perl-suid", pkgver:"5.8.7-5ubuntu1.2")) flag++;

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
