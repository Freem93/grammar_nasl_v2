#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-902-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44688);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/01 21:21:53 $");

  script_cve_id("CVE-2010-0277", "CVE-2010-0420", "CVE-2010-0423");
  script_osvdb_id(61625, 61626, 62439, 62440);
  script_xref(name:"USN", value:"902-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 / 9.10 : pidgin vulnerabilities (USN-902-1)");
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
"Fabian Yamaguchi discovered that Pidgin incorrectly validated all
fields of an incoming message in the MSN protocol handler. A remote
attacker could send a specially crafted message and cause Pidgin to
crash, leading to a denial of service. (CVE-2010-0277)

Sadrul Habib Chowdhury discovered that Pidgin incorrectly handled
certain nicknames in Finch group chat rooms. A remote attacker could
use a specially crafted nickname and cause Pidgin to crash, leading to
a denial of service. (CVE-2010-0420)

Antti Hayrynen discovered that Pidgin incorrectly handled large
numbers of smileys. A remote attacker could send a specially crafted
message and cause Pidgin to become unresponsive, leading to a denial
of service. (CVE-2010-0423).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:finch-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gaim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpurple-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpurple-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpurple0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pidgin-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pidgin-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pidgin-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"finch", pkgver:"2.4.1-1ubuntu2.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"finch-dev", pkgver:"2.4.1-1ubuntu2.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gaim", pkgver:"2.4.1-1ubuntu2.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpurple-bin", pkgver:"2.4.1-1ubuntu2.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpurple-dev", pkgver:"2.4.1-1ubuntu2.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpurple0", pkgver:"2.4.1-1ubuntu2.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pidgin", pkgver:"1:2.4.1-1ubuntu2.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pidgin-data", pkgver:"2.4.1-1ubuntu2.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pidgin-dbg", pkgver:"2.4.1-1ubuntu2.9")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"pidgin-dev", pkgver:"2.4.1-1ubuntu2.9")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"finch", pkgver:"2.5.2-0ubuntu1.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"finch-dev", pkgver:"2.5.2-0ubuntu1.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpurple-bin", pkgver:"2.5.2-0ubuntu1.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpurple-dev", pkgver:"2.5.2-0ubuntu1.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpurple0", pkgver:"2.5.2-0ubuntu1.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pidgin", pkgver:"1:2.5.2-0ubuntu1.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pidgin-data", pkgver:"2.5.2-0ubuntu1.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pidgin-dbg", pkgver:"2.5.2-0ubuntu1.7")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"pidgin-dev", pkgver:"2.5.2-0ubuntu1.7")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"finch", pkgver:"2.5.5-1ubuntu8.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"finch-dev", pkgver:"2.5.5-1ubuntu8.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpurple-bin", pkgver:"2.5.5-1ubuntu8.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpurple-dev", pkgver:"2.5.5-1ubuntu8.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpurple0", pkgver:"2.5.5-1ubuntu8.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pidgin", pkgver:"1:2.5.5-1ubuntu8.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pidgin-data", pkgver:"2.5.5-1ubuntu8.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pidgin-dbg", pkgver:"2.5.5-1ubuntu8.6")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"pidgin-dev", pkgver:"2.5.5-1ubuntu8.6")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"finch", pkgver:"2.6.2-1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"finch-dev", pkgver:"2.6.2-1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpurple-bin", pkgver:"2.6.2-1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpurple-dev", pkgver:"2.6.2-1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpurple0", pkgver:"2.6.2-1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"pidgin", pkgver:"1:2.6.2-1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"pidgin-data", pkgver:"2.6.2-1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"pidgin-dbg", pkgver:"2.6.2-1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"pidgin-dev", pkgver:"2.6.2-1ubuntu7.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-dev / gaim / libpurple-bin / libpurple-dev / etc");
}
