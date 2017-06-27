#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-626-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33827);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2008-2785", "CVE-2008-2933");
  script_bugtraq_id(29802, 30242);
  script_osvdb_id(47465);
  script_xref(name:"USN", value:"626-2");

  script_name(english:"Ubuntu 8.04 LTS : devhelp, epiphany-browser, midbrowser, yelp update (USN-626-2)");
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
"USN-626-1 fixed vulnerabilities in xulrunner-1.9. The changes required
that Devhelp, Epiphany, Midbrowser and Yelp also be updated to use the
new xulrunner-1.9.

A flaw was discovered in the browser engine. A variable could be made
to overflow causing the browser to crash. If a user were tricked into
opening a malicious web page, an attacker could cause a denial of
service or possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2008-2785)

Billy Rios discovered that Firefox and xulrunner, as used by
browsers such as Epiphany, did not properly perform URI
splitting with pipe symbols when passed a command-line URI.
If Firefox or xulrunner were passed a malicious URL, an
attacker may be able to execute local content with chrome
privileges. (CVE-2008-2933).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:devhelp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:epiphany-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:epiphany-browser-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:epiphany-browser-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:epiphany-browser-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:epiphany-gecko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdevhelp-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdevhelp-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:midbrowser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/05");
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
if (! ereg(pattern:"^(8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"devhelp", pkgver:"0.19-1ubuntu1.8.04.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"devhelp-common", pkgver:"0.19-1ubuntu1.8.04.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"epiphany-browser", pkgver:"2.22.2-0ubuntu0.8.04.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"epiphany-browser-data", pkgver:"2.22.2-0ubuntu0.8.04.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"epiphany-browser-dbg", pkgver:"2.22.2-0ubuntu0.8.04.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"epiphany-browser-dev", pkgver:"2.22.2-0ubuntu0.8.04.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"epiphany-gecko", pkgver:"2.22.2-0ubuntu0.8.04.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libdevhelp-1-0", pkgver:"0.19-1ubuntu1.8.04.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libdevhelp-1-dev", pkgver:"0.19-1ubuntu1.8.04.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"midbrowser", pkgver:"0.3.0rc1a-1~8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"yelp", pkgver:"2.22.1-0ubuntu2.8.04.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-common / epiphany-browser / epiphany-browser-data / etc");
}
