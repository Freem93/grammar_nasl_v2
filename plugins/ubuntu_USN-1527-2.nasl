#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1527-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62036);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/06/14 17:29:38 $");

  script_cve_id("CVE-2012-0876", "CVE-2012-1148");
  script_bugtraq_id(52379);
  script_osvdb_id(80892, 80893);
  script_xref(name:"USN", value:"1527-2");

  script_name(english:"Ubuntu 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : xmlrpc-c vulnerabilities (USN-1527-2)");
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
"USN-1527-1 fixed vulnerabilities in Expat. This update provides the
corresponding updates for XML-RPC for C and C++. Both issues described
in the original advisory affected XML-RPC for C and C++ in Ubuntu
10.04 LTS, 11.04, 11.10 and 12.04 LTS.

It was discovered that Expat computed hash values without restricting
the ability to trigger hash collisions predictably. If a user or
application linked against Expat were tricked into opening a crafted
XML file, an attacker could cause a denial of service by consuming
excessive CPU resources. (CVE-2012-0876)

Tim Boddy discovered that Expat did not properly handle
memory reallocation when processing XML files. If a user or
application linked against Expat were tricked into opening a
crafted XML file, an attacker could cause a denial of
service by consuming excessive memory resources. This issue
only affected Ubuntu 8.04 LTS, 10.04 LTS, 11.04 and 11.10.
(CVE-2012-1148).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libxmlrpc-core-c3 and / or libxmlrpc-core-c3-0
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmlrpc-core-c3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmlrpc-core-c3-0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/11");
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
if (! ereg(pattern:"^(10\.04|11\.04|11\.10|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.04 / 11.10 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libxmlrpc-core-c3", pkgver:"1.06.27-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libxmlrpc-core-c3-0", pkgver:"1.16.32-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libxmlrpc-core-c3-0", pkgver:"1.16.32-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libxmlrpc-core-c3", pkgver:"1.16.33-3.1ubuntu5.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxmlrpc-core-c3 / libxmlrpc-core-c3-0");
}
