#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2812-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86897);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/05/24 17:52:27 $");

  script_cve_id("CVE-2015-1819", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8035");
  script_osvdb_id(120600, 121175, 129696);
  script_xref(name:"USN", value:"2812-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.04 / 15.10 : libxml2 vulnerabilities (USN-2812-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Florian Weimer discovered that libxml2 incorrectly handled certain XML
data. If a user or automated system were tricked into opening a
specially crafted document, an attacker could possibly cause resource
consumption, resulting in a denial of service. This issue only
affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 15.04.
(CVE-2015-1819)

Michal Zalewski discovered that libxml2 incorrectly handled certain
XML data. If a user or automated system were tricked into opening a
specially crafted document, an attacker could possibly cause libxml2
to crash, resulting in a denial of service. This issue only affected
Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-7941)

Kostya Serebryany discovered that libxml2 incorrectly handled certain
XML data. If a user or automated system were tricked into opening a
specially crafted document, an attacker could possibly cause libxml2
to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2015-7942)

Gustavo Grieco discovered that libxml2 incorrectly handled certain XML
data. If a user or automated system were tricked into opening a
specially crafted document, an attacker could possibly cause libxml2
to crash, resulting in a denial of service. This issue only affected
Ubuntu 14.04 LTS. (CVE-2015-8035).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/17");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libxml2", pkgver:"2.7.8.dfsg-5.1ubuntu4.12")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libxml2", pkgver:"2.9.1+dfsg1-3ubuntu4.5")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libxml2", pkgver:"2.9.2+dfsg1-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libxml2", pkgver:"2.9.2+zdfsg1-4ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2");
}
