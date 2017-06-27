#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2030-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70962);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/25 16:34:54 $");

  script_cve_id("CVE-2013-1739", "CVE-2013-1741", "CVE-2013-5605", "CVE-2013-5606");
  script_bugtraq_id(62966, 63736, 63737, 63738);
  script_osvdb_id(98402, 99746, 99747, 99748);
  script_xref(name:"USN", value:"2030-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 12.10 / 13.04 / 13.10 : nss vulnerabilities (USN-2030-1)");
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
"Multiple security issues were discovered in NSS. If a user were
tricked into connecting to a malicious server, an attacker could
possibly exploit these to cause a denial of service via application
crash, potentially execute arbitrary code, or lead to information
disclosure.

This update also adds TLS v1.2 support to Ubuntu 10.04 LTS, Ubuntu
12.04 LTS, Ubuntu 12.10, and Ubuntu 13.04.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libnss3 and / or libnss3-1d packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3-1d");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/19");
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
if (! ereg(pattern:"^(10\.04|12\.04|12\.10|13\.04|13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 12.10 / 13.04 / 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libnss3-1d", pkgver:"3.15.3-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libnss3", pkgver:"3.15.3-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libnss3", pkgver:"3.15.3-0ubuntu0.12.10.1")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"libnss3", pkgver:"2:3.15.3-0ubuntu0.13.04.1")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"libnss3", pkgver:"2:3.15.3-0ubuntu0.13.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnss3 / libnss3-1d");
}
