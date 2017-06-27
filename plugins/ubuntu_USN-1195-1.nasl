#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1195-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55967);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/26 16:14:09 $");

  script_cve_id("CVE-2010-1824", "CVE-2010-2646", "CVE-2010-2651", "CVE-2010-2900", "CVE-2010-2901", "CVE-2010-3120", "CVE-2010-3254", "CVE-2010-3812", "CVE-2010-3813", "CVE-2010-4040", "CVE-2010-4042", "CVE-2010-4197", "CVE-2010-4198", "CVE-2010-4199", "CVE-2010-4204", "CVE-2010-4206", "CVE-2010-4492", "CVE-2010-4493", "CVE-2010-4577", "CVE-2010-4578", "CVE-2011-0482", "CVE-2011-0778");
  script_bugtraq_id(41976, 44241, 44646, 44954, 44960, 45170, 45390, 45718, 45719, 45720, 45721, 45722, 45788, 46144, 46677);
  script_osvdb_id(66044, 66049, 66748, 66749, 67467, 67862, 68102, 68841, 68843, 69163, 69164, 69165, 69170, 69172, 69433, 69434, 69671, 69672, 70105, 70106, 70465, 75255);
  script_xref(name:"USN", value:"1195-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 : webkit vulnerabilities (USN-1195-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
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
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libwebkit-1.0-2 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkit-1.0-2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libwebkit-1.0-2", pkgver:"1.2.7-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libwebkit-1.0-2", pkgver:"1.2.7-0ubuntu0.10.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwebkit-1.0-2");
}
