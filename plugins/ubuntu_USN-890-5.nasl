#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-890-5. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44669);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/01 21:21:53 $");

  script_cve_id("CVE-2009-2625", "CVE-2009-3560", "CVE-2009-3720");
  script_bugtraq_id(36097, 37203);
  script_osvdb_id(59737, 60797);
  script_xref(name:"USN", value:"890-5");

  script_name(english:"Ubuntu 9.10 : xmlrpc-c vulnerabilities (USN-890-5)");
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
"USN-890-1 fixed vulnerabilities in Expat. This update provides the
corresponding updates for XML-RPC for C and C++.

Jukka Taimisto, Tero Rontti and Rauli Kaksonen discovered that Expat
did not properly process malformed XML. If a user or application
linked against Expat were tricked into opening a crafted XML file, an
attacker could cause a denial of service via application crash.
(CVE-2009-2625, CVE-2009-3720)

It was discovered that Expat did not properly process
malformed UTF-8 sequences. If a user or application linked
against Expat were tricked into opening a crafted XML file,
an attacker could cause a denial of service via application
crash. (CVE-2009-3560).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmlrpc-c3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmlrpc-c3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmlrpc-core-c3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmlrpc-core-c3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xml-rpc-api2cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xml-rpc-api2txt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/19");
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
if (! ereg(pattern:"^(9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.10", pkgname:"libxmlrpc-c3", pkgver:"1.06.27-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libxmlrpc-c3-dev", pkgver:"1.06.27-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libxmlrpc-core-c3", pkgver:"1.06.27-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libxmlrpc-core-c3-dev", pkgver:"1.06.27-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xml-rpc-api2cpp", pkgver:"1.06.27-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"xml-rpc-api2txt", pkgver:"1.06.27-1ubuntu6.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxmlrpc-c3 / libxmlrpc-c3-dev / libxmlrpc-core-c3 / etc");
}
