#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-554-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29239);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2007-5935", "CVE-2007-5936", "CVE-2007-5937");
  script_xref(name:"USN", value:"554-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : tetex-bin, texlive-bin vulnerabilities (USN-554-1)");
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
"Bastien Roucaries discovered that dvips as included in tetex-bin and
texlive-bin did not properly perform bounds checking. If a user or
automated system were tricked into processing a specially crafted dvi
file, dvips could be made to crash and execute code as the user
invoking the program. (CVE-2007-5935)

Joachim Schrod discovered that the dviljk utilities created temporary
files in an insecure way. Local users could exploit a race condition
to create or overwrite files with the privileges of the user invoking
the program. (CVE-2007-5936)

Joachim Schrod discovered that the dviljk utilities did not perform
bounds checking in many instances. If a user or automated system were
tricked into processing a specially crafted dvi file, the dviljk
utilities could be made to crash and execute code as the user invoking
the program. (CVE-2007-5937).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpathsea-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpathsea4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpathsea4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tetex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-base-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-extra-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-lang-indic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-metapost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-music");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-omega");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-xetex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/07");
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

if (ubuntu_check(osver:"6.06", pkgname:"libkpathsea4", pkgver:"3.0-13ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkpathsea4-dev", pkgver:"3.0-13ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"tetex-bin", pkgver:"3.0-13ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libkpathsea-dev", pkgver:"3.0-17ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libkpathsea4", pkgver:"3.0-17ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"tetex-bin", pkgver:"3.0-17ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libkpathsea-dev", pkgver:"3.0-27ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libkpathsea4", pkgver:"3.0-27ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"tetex-bin", pkgver:"3.0-27ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libkpathsea-dev", pkgver:"2007-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libkpathsea4", pkgver:"2007-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"texlive-base-bin", pkgver:"2007-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"texlive-extra-utils", pkgver:"2007-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"texlive-font-utils", pkgver:"2007-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"texlive-lang-indic", pkgver:"2007-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"texlive-metapost", pkgver:"2007-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"texlive-music", pkgver:"2007-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"texlive-omega", pkgver:"2007-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"texlive-xetex", pkgver:"2007-12ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libkpathsea-dev / libkpathsea4 / libkpathsea4-dev / tetex-bin / etc");
}
