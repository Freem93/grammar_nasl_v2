#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1397-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58325);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

  script_cve_id("CVE-2007-5925", "CVE-2008-3963", "CVE-2008-4098", "CVE-2008-4456", "CVE-2008-7247", "CVE-2009-2446", "CVE-2009-4019", "CVE-2009-4030", "CVE-2009-4484", "CVE-2010-1621", "CVE-2010-1626", "CVE-2010-1848", "CVE-2010-1849", "CVE-2010-1850", "CVE-2010-2008", "CVE-2010-3677", "CVE-2010-3678", "CVE-2010-3679", "CVE-2010-3680", "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3683", "CVE-2010-3833", "CVE-2010-3834", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3839", "CVE-2010-3840", "CVE-2011-2262", "CVE-2012-0075", "CVE-2012-0087", "CVE-2012-0101", "CVE-2012-0102", "CVE-2012-0112", "CVE-2012-0113", "CVE-2012-0114", "CVE-2012-0115", "CVE-2012-0116", "CVE-2012-0117", "CVE-2012-0118", "CVE-2012-0119", "CVE-2012-0120", "CVE-2012-0484", "CVE-2012-0485", "CVE-2012-0486", "CVE-2012-0487", "CVE-2012-0488", "CVE-2012-0489", "CVE-2012-0490", "CVE-2012-0491", "CVE-2012-0492", "CVE-2012-0493", "CVE-2012-0494", "CVE-2012-0495", "CVE-2012-0496");
  script_bugtraq_id(26353, 29106, 31081, 31486, 35609, 37075, 37297, 37640, 37943, 38043, 39543, 40100, 40106, 40109, 40257, 41198, 42596, 42598, 42599, 42625, 42633, 42638, 42646, 43676, 51488, 51493, 51502, 51504, 51505, 51508, 51509, 51519, 51520, 51526);
  script_osvdb_id(44937, 48021, 48710, 51171, 55734, 60488, 60489, 60664, 60665, 61956, 63903, 64586, 64587, 64588, 64843, 65851, 67378, 67379, 67380, 67381, 67383, 67384, 69000, 69001, 69387, 69390, 69391, 69392, 69393, 69394, 69395, 78368, 78369, 78370, 78371, 78372, 78373, 78374, 78375, 78376, 78377, 78378, 78379, 78380, 78381, 78382, 78383, 78384, 78385, 78386, 78387, 78388, 78389, 78390, 78391, 78392, 78393, 78394);
  script_xref(name:"USN", value:"1397-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 / 11.10 : mysql-5.1, mysql-dfsg-5.0, mysql-dfsg-5.1 vulnerabilities (USN-1397-1)");
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
"Multiple security issues were discovered in MySQL and this update
includes new upstream MySQL versions to fix these issues.

MySQL has been updated to 5.1.61 in Ubuntu 10.04 LTS, Ubuntu 10.10,
Ubuntu 11.04 and Ubuntu 11.10. Ubuntu 8.04 LTS has been updated to
MySQL 5.0.95.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the following for more information :

http://dev.mysql.com/doc/refman/5.1/en/news-5-1-x.html
http://dev.mysql.com/doc/refman/5.0/en/news-5-0-x.html
http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.ht
ml.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected mysql-server-5.0 and / or mysql-server-5.1
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MySQL yaSSL CertDecoder::GetName Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_cwe_id(20, 59, 79, 119, 134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server-5.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/13");
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
if (! ereg(pattern:"^(8\.04|10\.04|10\.10|11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 10.10 / 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"mysql-server-5.0", pkgver:"5.0.95-0ubuntu1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mysql-server-5.1", pkgver:"5.1.61-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"mysql-server-5.1", pkgver:"5.1.61-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"mysql-server-5.1", pkgver:"5.1.61-0ubuntu0.11.04.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"mysql-server-5.1", pkgver:"5.1.61-0ubuntu0.11.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql-server-5.0 / mysql-server-5.1");
}
