#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1482-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61568);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/25 16:19:24 $");

  script_cve_id("CVE-2012-1457", "CVE-2012-1458", "CVE-2012-1459");
  script_xref(name:"USN", value:"1482-3");

  script_name(english:"Ubuntu 11.04 / 11.10 / 12.04 LTS : clamav regression (USN-1482-3)");
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
"USN-1482-1 fixed vulnerabilities in ClamAV. The updated package could
fail to properly scan files in some situations. This update fixes the
problem.

We apologize for the inconvenience.

It was discovered that ClamAV incorrectly handled certain malformed
TAR archives. A remote attacker could create a specially crafted TAR
file containing malware that could escape being detected.
(CVE-2012-1457, CVE-2012-1459)

It was discovered that ClamAV incorrectly handled certain
malformed CHM files. A remote attacker could create a
specially crafted CHM file containing malware that could
escape being detected. (CVE-2012-1458).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected clamav and / or libclamav6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclamav6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2016 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(11\.04|11\.10|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.04 / 11.10 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"11.04", pkgname:"clamav", pkgver:"0.97.5+dfsg-1ubuntu0.11.04.3")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libclamav6", pkgver:"0.97.5+dfsg-1ubuntu0.11.04.3")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"clamav", pkgver:"0.97.5+dfsg-1ubuntu0.11.10.3")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libclamav6", pkgver:"0.97.5+dfsg-1ubuntu0.11.10.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"clamav", pkgver:"0.97.5+dfsg-1ubuntu0.12.04.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libclamav6", pkgver:"0.97.5+dfsg-1ubuntu0.12.04.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav / libclamav6");
}
