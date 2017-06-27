#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3272-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99726);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/05/11 13:20:58 $");

  script_cve_id("CVE-2016-10217", "CVE-2016-10219", "CVE-2016-10220", "CVE-2017-5951", "CVE-2017-7207", "CVE-2017-8291");
  script_osvdb_id(154062, 154925, 154980, 154981, 154982, 156431);
  script_xref(name:"USN", value:"3272-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 / 17.04 : ghostscript vulnerabilities (USN-3272-1)");
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
"It was discovered that Ghostscript improperly handled parameters to
the rsdparams and eqproc commands. An attacker could use these to
craft a malicious document that could disable -dSAFER protections,
thereby allowing the execution of arbitrary code, or cause a denial of
service (application crash). (CVE-2017-8291)

Kamil Frankowicz discovered a use-after-free vulnerability in the
color management module of Ghostscript. An attacker could use this to
cause a denial of service (application crash). (CVE-2016-10217)

Kamil Frankowicz discovered a divide-by-zero error in the scan
conversion code in Ghostscript. An attacker could use this to cause a
denial of service (application crash). (CVE-2016-10219)

Kamil Frankowicz discovered multiple NULL pointer dereference errors
in Ghostscript. An attacker could use these to cause a denial of
service (application crash). (CVE-2016-10220, CVE-2017-5951,
CVE-2017-7207).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs9-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017 Canonical, Inc. / NASL script (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04|16\.10|17\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 16.10 / 17.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"ghostscript", pkgver:"9.05~dfsg-0ubuntu4.5")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"ghostscript-x", pkgver:"9.05~dfsg-0ubuntu4.5")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgs9", pkgver:"9.05~dfsg-0ubuntu4.5")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgs9-common", pkgver:"9.05~dfsg-0ubuntu4.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"ghostscript", pkgver:"9.10~dfsg-0ubuntu10.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"ghostscript-x", pkgver:"9.10~dfsg-0ubuntu10.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libgs9", pkgver:"9.10~dfsg-0ubuntu10.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libgs9-common", pkgver:"9.10~dfsg-0ubuntu10.7")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"ghostscript", pkgver:"9.18~dfsg~0-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"ghostscript-x", pkgver:"9.18~dfsg~0-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libgs9", pkgver:"9.18~dfsg~0-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libgs9-common", pkgver:"9.18~dfsg~0-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"ghostscript", pkgver:"9.19~dfsg+1-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"ghostscript-x", pkgver:"9.19~dfsg+1-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libgs9", pkgver:"9.19~dfsg+1-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libgs9-common", pkgver:"9.19~dfsg+1-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"ghostscript", pkgver:"9.19~dfsg+1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"ghostscript-x", pkgver:"9.19~dfsg+1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"libgs9", pkgver:"9.19~dfsg+1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"libgs9-common", pkgver:"9.19~dfsg+1-0ubuntu7.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-x / libgs9 / libgs9-common");
}
