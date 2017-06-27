#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1129-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55090);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2010-1168", "CVE-2010-1447", "CVE-2010-2761", "CVE-2010-4410", "CVE-2010-4411", "CVE-2011-1487");
  script_bugtraq_id(40302, 40305, 45145, 47124);
  script_osvdb_id(64756, 65683, 69588, 69589, 75047);
  script_xref(name:"USN", value:"1129-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 10.04 LTS / 10.10 / 11.04 : perl vulnerabilities (USN-1129-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Safe.pm Perl module incorrectly handled
Safe::reval and Safe::rdo access restrictions. An attacker could use
this flaw to bypass intended restrictions and possibly execute
arbitrary code. (CVE-2010-1168, CVE-2010-1447)

It was discovered that the CGI.pm Perl module incorrectly handled
certain MIME boundary strings. An attacker could use this flaw to
inject arbitrary HTTP headers and perform HTTP response splitting and
cross-site scripting attacks. This issue only affected Ubuntu 6.06
LTS, 8.04 LTS, 10.04 LTS and 10.10. (CVE-2010-2761, CVE-2010-4411)

It was discovered that the CGI.pm Perl module incorrectly handled
newline characters. An attacker could use this flaw to inject
arbitrary HTTP headers and perform HTTP response splitting and
cross-site scripting attacks. This issue only affected Ubuntu 6.06
LTS, 8.04 LTS, 10.04 LTS and 10.10. (CVE-2010-4410)

It was discovered that the lc, lcfirst, uc, and ucfirst functions did
not properly apply the taint attribute when processing tainted input.
An attacker could use this flaw to bypass intended restrictions. This
issue only affected Ubuntu 8.04 LTS, 10.04 LTS and 10.10.
(CVE-2011-1487).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/13");
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
if (! ereg(pattern:"^(6\.06|8\.04|10\.04|10\.10|11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 10.04 / 10.10 / 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"perl", pkgver:"5.8.7-10ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"perl", pkgver:"5.8.8-12ubuntu0.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"perl", pkgver:"5.10.1-8ubuntu2.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"perl", pkgver:"5.10.1-12ubuntu2.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"perl", pkgver:"5.10.1-17ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl");
}
