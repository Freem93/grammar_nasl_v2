#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-835-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41046);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-3746", "CVE-2009-2474");
  script_bugtraq_id(30710, 36079);
  script_osvdb_id(47676, 57514);
  script_xref(name:"USN", value:"835-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : neon, neon27 vulnerabilities (USN-835-1)");
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
"Joe Orton discovered that neon did not correctly handle SSL
certificates with zero bytes in the Common Name. A remote attacker
could exploit this to perform a man in the middle attack to view
sensitive information or alter encrypted communications.

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
  script_cwe_id(20, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libneon25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libneon25-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libneon25-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libneon27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libneon27-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libneon27-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libneon27-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libneon27-gnutls-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libneon27-gnutls-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libneon25", pkgver:"0.25.5.dfsg-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libneon25-dbg", pkgver:"0.25.5.dfsg-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libneon25-dev", pkgver:"0.25.5.dfsg-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libneon27", pkgver:"0.27.2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libneon27-dbg", pkgver:"0.27.2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libneon27-dev", pkgver:"0.27.2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libneon27-gnutls", pkgver:"0.27.2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libneon27-gnutls-dbg", pkgver:"0.27.2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libneon27-gnutls-dev", pkgver:"0.27.2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libneon27", pkgver:"0.28.2-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libneon27-dbg", pkgver:"0.28.2-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libneon27-dev", pkgver:"0.28.2-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libneon27-gnutls", pkgver:"0.28.2-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libneon27-gnutls-dbg", pkgver:"0.28.2-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libneon27-gnutls-dev", pkgver:"0.28.2-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libneon25-dev", pkgver:"0.28.2-6.1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libneon27", pkgver:"0.28.2-6.1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libneon27-dbg", pkgver:"0.28.2-6.1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libneon27-dev", pkgver:"0.28.2-6.1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libneon27-gnutls", pkgver:"0.28.2-6.1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libneon27-gnutls-dbg", pkgver:"0.28.2-6.1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libneon27-gnutls-dev", pkgver:"0.28.2-6.1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libneon25 / libneon25-dbg / libneon25-dev / libneon27 / etc");
}
