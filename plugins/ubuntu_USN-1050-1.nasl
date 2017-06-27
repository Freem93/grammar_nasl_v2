#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1050-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52527);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2010-1585", "CVE-2011-0053", "CVE-2011-0061", "CVE-2011-0062");
  script_bugtraq_id(46368, 46645, 46647, 46651);
  script_xref(name:"USN", value:"1050-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 : thunderbird vulnerabilities (USN-1050-1)");
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
"Jesse Ruderman, Igor Bukanov, Olli Pettay, Gary Kwong, Jeff Walden,
Henry Sivonen, Martijn Wargers, David Baron and Marcia Knous
discovered several memory issues in the browser engine. An attacker
could exploit these to crash the browser or possibly run arbitrary
code as the user invoking the program. (CVE-2011-0053, CVE-2011-0062)

Roberto Suggi Liverani discovered a possible issue with unsafe
JavaScript execution in chrome documents. A malicious extension could
exploit this to execute arbitrary code with chrome privlieges.
(CVE-2010-1585)

Jordi Chancel discovered a buffer overlow in the JPEG decoding engine.
An attacker could exploit this to crash the browser or possibly run
arbitrary code as the user invoking the program. (CVE-2011-0061).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-gnome-support-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"thunderbird", pkgver:"3.1.8+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-dbg", pkgver:"3.1.8+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-dev", pkgver:"3.1.8+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-gnome-support", pkgver:"3.1.8+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"thunderbird-gnome-support-dbg", pkgver:"3.1.8+build3+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"thunderbird", pkgver:"3.1.8+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"thunderbird-dbg", pkgver:"3.1.8+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"thunderbird-dev", pkgver:"3.1.8+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"thunderbird-gnome-support", pkgver:"3.1.8+build3+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"thunderbird-gnome-support-dbg", pkgver:"3.1.8+build3+nobinonly-0ubuntu0.10.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-dbg / thunderbird-dev / etc");
}
