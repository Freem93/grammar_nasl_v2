#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-601-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31967);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/27 14:29:19 $");

  script_cve_id("CVE-2007-6239", "CVE-2008-1612");
  script_bugtraq_id(28693);
  script_xref(name:"USN", value:"601-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : squid vulnerability (USN-601-1)");
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
"It was discovered that Squid did not perform proper bounds checking
when processing cache update replies. A remote authenticated user may
be able to trigger an assertion error and cause a denial of service.
This vulnerability is due to an incorrect upstream fix for
CVE-2007-6239. (CVE-2008-1612).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squidclient");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/17");
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

if (ubuntu_check(osver:"6.06", pkgname:"squid", pkgver:"2.5.12-4ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"squid-cgi", pkgver:"2.5.12-4ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"squid-common", pkgver:"2.5.12-4ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"squidclient", pkgver:"2.5.12-4ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"squid", pkgver:"2.6.1-3ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"squid-cgi", pkgver:"2.6.1-3ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"squid-common", pkgver:"2.6.1-3ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"squidclient", pkgver:"2.6.1-3ubuntu1.7")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"squid", pkgver:"2.6.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"squid-cgi", pkgver:"2.6.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"squid-common", pkgver:"2.6.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"squidclient", pkgver:"2.6.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"squid", pkgver:"2.6.14-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"squid-cgi", pkgver:"2.6.14-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"squid-common", pkgver:"2.6.14-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"squidclient", pkgver:"2.6.14-1ubuntu2.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid / squid-cgi / squid-common / squidclient");
}
