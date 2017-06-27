#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2540-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82024);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/24 17:37:08 $");

  script_cve_id("CVE-2014-8155", "CVE-2015-0282", "CVE-2015-0294");
  script_bugtraq_id(73119, 73162);
  script_osvdb_id(118749, 119020, 119405);
  script_xref(name:"USN", value:"2540-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 14.04 LTS / 14.10 : gnutls26, gnutls28 vulnerabilities (USN-2540-1)");
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
"It was discovered that GnuTLS did not perform date and time checks on
CA certificates, contrary to expectations. This issue only affected
Ubuntu 10.04 LTS. (CVE-2014-8155)

Nikos Mavrogiannopoulos discovered that GnuTLS incorrectly verified
that signature algorithms matched. A remote attacker could possibly
use this issue to downgrade to a disallowed algorithm. This issue only
affected Ubuntu 10.04 LTS, Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2015-0282)

It was discovered that GnuTLS incorrectly verified certificate
algorithms. A remote attacker could possibly use this issue to
downgrade to a disallowed algorithm. (CVE-2015-0294).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgnutls-deb0-28 and / or libgnutls26 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls-deb0-28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls26");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|12\.04|14\.04|14\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 14.04 / 14.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libgnutls26", pkgver:"2.8.5-2ubuntu0.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libgnutls26", pkgver:"2.12.14-5ubuntu3.9")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libgnutls26", pkgver:"2.12.23-12ubuntu2.2")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"libgnutls-deb0-28", pkgver:"3.2.16-1ubuntu2.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgnutls-deb0-28 / libgnutls26");
}
