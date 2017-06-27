#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-599-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31848);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/27 14:29:19 $");

  script_cve_id("CVE-2008-0411");
  script_bugtraq_id(28017);
  script_osvdb_id(42310);
  script_xref(name:"USN", value:"599-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : ghostscript, gs-esp, gs-gpl vulnerability (USN-599-1)");
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
"Chris Evans discovered that Ghostscript contained a buffer overflow in
its color space handling code. If a user or automated system were
tricked into opening a crafted Postscript file, an attacker could
cause a denial of service or execute arbitrary code with privileges of
the user invoking the program. (CVE-2008-0411).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs-aladdin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs-esp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs-esp-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gs-gpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs-esp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs-esp8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/11");
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

if (ubuntu_check(osver:"6.06", pkgname:"gs", pkgver:"8.15-4ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gs-esp", pkgver:"8.15.2.dfsg.0ubuntu1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gs-gpl", pkgver:"8.15-4ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"gs", pkgver:"8.50-1.1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"gs-esp", pkgver:"8.15.2.dfsg.0ubuntu1-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"gs-gpl", pkgver:"8.50-1.1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libgs-esp-dev", pkgver:"8.15.2.dfsg.0ubuntu1-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libgs-esp8", pkgver:"8.15.2.dfsg.0ubuntu1-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"gs", pkgver:"8.54.dfsg.1-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"gs-esp", pkgver:"8.15.4.dfsg.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"gs-esp-x", pkgver:"8.15.4.dfsg.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"gs-gpl", pkgver:"8.54.dfsg.1-5ubuntu0.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libgs-esp-dev", pkgver:"8.15.4.dfsg.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libgs-esp8", pkgver:"8.15.4.dfsg.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ghostscript", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ghostscript-doc", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ghostscript-x", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gs", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gs-aladdin", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gs-common", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gs-esp", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gs-esp-x", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gs-gpl", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libgs-dev", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libgs-esp-dev", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libgs8", pkgver:"8.61.dfsg.1~svn8187-0ubuntu3.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-doc / ghostscript-x / gs / gs-aladdin / etc");
}
