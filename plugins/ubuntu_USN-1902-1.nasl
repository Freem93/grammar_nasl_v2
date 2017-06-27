#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1902-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67224);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/25 16:27:06 $");

  script_cve_id("CVE-2013-4073");
  script_bugtraq_id(60843);
  script_osvdb_id(94628);
  script_xref(name:"USN", value:"1902-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.04 : ruby1.8, ruby1.9.1 vulnerability (USN-1902-1)");
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
"William (B.J.) Snow Orvis discovered that Ruby incorrectly verified
the hostname in SSL certificates. An attacker could trick Ruby into
trusting a rogue server certificate, which was signed by a trusted
certificate authority, to perform a man-in-the-middle attack.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|12\.10|13\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10 / 13.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libruby1.8", pkgver:"1.8.7.352-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libruby1.9.1", pkgver:"1.9.3.0-1ubuntu2.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"ruby1.8", pkgver:"1.8.7.352-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"ruby1.9.1", pkgver:"1.9.3.0-1ubuntu2.7")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libruby1.8", pkgver:"1.8.7.358-4ubuntu0.3")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libruby1.9.1", pkgver:"1.9.3.194-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"ruby1.8", pkgver:"1.8.7.358-4ubuntu0.3")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"ruby1.9.1", pkgver:"1.9.3.194-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"libruby1.8", pkgver:"1.8.7.358-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"libruby1.9.1", pkgver:"1.9.3.194-8.1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"ruby1.8", pkgver:"1.8.7.358-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"ruby1.9.1", pkgver:"1.9.3.194-8.1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libruby1.8 / libruby1.9.1 / ruby1.8 / ruby1.9.1");
}
