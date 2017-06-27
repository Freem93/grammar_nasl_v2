#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-700-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37746);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2007-4829", "CVE-2008-1927", "CVE-2008-5302", "CVE-2008-5303");
  script_bugtraq_id(12767, 26355, 28928);
  script_osvdb_id(40410);
  script_xref(name:"USN", value:"700-2");

  script_name(english:"Ubuntu 8.04 LTS : perl regression (USN-700-2)");
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
"USN-700-1 fixed vulnerabilities in Perl. Due to problems with the
Ubuntu 8.04 build, some Perl .ph files were missing from the resulting
update. This update fixes the problem. We apologize for the
inconvenience.

Jonathan Smith discovered that the Archive::Tar Perl module did not
correctly handle symlinks when extracting archives. If a user or
automated system were tricked into opening a specially crafted tar
file, a remote attacker could over-write arbitrary files.
(CVE-2007-4829)

Tavis Ormandy and Will Drewry discovered that Perl did not
correctly handle certain utf8 characters in regular
expressions. If a user or automated system were tricked into
using a specially crafted expression, a remote attacker
could crash the application, leading to a denial of service.
Ubuntu 8.10 was not affected by this issue. (CVE-2008-1927)

A race condition was discovered in the File::Path Perl
module's rmtree function. If a local attacker successfully
raced another user's call of rmtree, they could create
arbitrary setuid binaries. Ubuntu 6.06 and 8.10 were not
affected by this issue. (CVE-2008-5302)

A race condition was discovered in the File::Path Perl
module's rmtree function. If a local attacker successfully
raced another user's call of rmtree, they could delete
arbitrary files. Ubuntu 6.06 was not affected by this issue.
(CVE-2008-5303).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 362, 399);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/15");
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
if (! ereg(pattern:"^(8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libcgi-fast-perl", pkgver:"5.8.8-12ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libperl-dev", pkgver:"5.8.8-12ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libperl5.8", pkgver:"5.8.8-12ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"perl", pkgver:"5.8.8-12ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"perl-base", pkgver:"5.8.8-12ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"perl-debug", pkgver:"5.8.8-12ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"perl-doc", pkgver:"5.8.8-12ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"perl-modules", pkgver:"5.8.8-12ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"perl-suid", pkgver:"5.8.8-12ubuntu0.4")) flag++;

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
