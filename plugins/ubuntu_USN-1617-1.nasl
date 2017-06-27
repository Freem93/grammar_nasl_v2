#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1617-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62707);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/25 16:19:25 $");

  script_cve_id("CVE-2011-3031", "CVE-2011-3038", "CVE-2011-3042", "CVE-2011-3043", "CVE-2011-3044", "CVE-2011-3051", "CVE-2011-3053", "CVE-2011-3059", "CVE-2011-3060", "CVE-2011-3064", "CVE-2011-3067", "CVE-2011-3076", "CVE-2011-3081", "CVE-2011-3086", "CVE-2011-3090", "CVE-2012-1521", "CVE-2012-3598", "CVE-2012-3601", "CVE-2012-3604", "CVE-2012-3611", "CVE-2012-3612", "CVE-2012-3617", "CVE-2012-3625", "CVE-2012-3626", "CVE-2012-3627", "CVE-2012-3628", "CVE-2012-3645", "CVE-2012-3652", "CVE-2012-3657", "CVE-2012-3669", "CVE-2012-3670", "CVE-2012-3671", "CVE-2012-3672", "CVE-2012-3674");
  script_bugtraq_id(52271, 52674, 52762, 52913, 53309, 53540, 54680, 55534);
  script_osvdb_id(79790, 79797, 79801, 79802, 79803, 80289, 80291, 80737, 80738, 80742, 81037, 81046, 81644, 81647, 81948, 81952, 84152, 84157, 84161, 84162, 84163, 84164, 84178, 84190, 84191, 84192, 85366, 85370, 85371, 85406, 85410, 85412, 85413, 85416);
  script_xref(name:"USN", value:"1617-1");

  script_name(english:"Ubuntu 12.04 LTS : webkit vulnerabilities (USN-1617-1)");
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
"A large number of security issues were discovered in the WebKit
browser and JavaScript engines. If a user were tricked into viewing a
malicious website, a remote attacker could exploit a variety of issues
related to web browser security, including cross-site scripting
attacks, denial of service attacks, and arbitrary code execution.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-3.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkitgtk-1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkitgtk-3.0-0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/26");
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
if (! ereg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libjavascriptcoregtk-1.0-0", pkgver:"1.8.3-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libjavascriptcoregtk-3.0-0", pkgver:"1.8.3-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libwebkitgtk-1.0-0", pkgver:"1.8.3-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libwebkitgtk-3.0-0", pkgver:"1.8.3-0ubuntu0.12.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjavascriptcoregtk-1.0-0 / libjavascriptcoregtk-3.0-0 / etc");
}
