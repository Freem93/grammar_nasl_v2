#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3216-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99121);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/04 13:36:41 $");

  script_cve_id("CVE-2017-5398", "CVE-2017-5399", "CVE-2017-5400", "CVE-2017-5401", "CVE-2017-5402", "CVE-2017-5403", "CVE-2017-5404", "CVE-2017-5405", "CVE-2017-5406", "CVE-2017-5407", "CVE-2017-5408", "CVE-2017-5410", "CVE-2017-5412", "CVE-2017-5413", "CVE-2017-5414", "CVE-2017-5415", "CVE-2017-5416", "CVE-2017-5417", "CVE-2017-5418", "CVE-2017-5419", "CVE-2017-5420", "CVE-2017-5421", "CVE-2017-5422", "CVE-2017-5426", "CVE-2017-5427");
  script_osvdb_id(144079, 147374, 153143, 153144, 153145, 153146, 153147, 153148, 153149, 153150, 153151, 153152, 153153, 153154, 153155, 153156, 153157, 153158, 153159, 153160, 153161, 153162, 153163, 153164, 153165, 153166, 153167, 153168, 153169, 153170, 153171, 153172, 153173, 153174, 153175, 153176, 153177, 153178, 153179, 153180, 153181, 153182, 153183, 153189, 153190, 153191, 153192, 153193, 153194, 153195, 153198, 153203, 153204, 153205, 153206, 153207, 153209, 153210, 153211, 153212, 153213, 153214, 153217, 153248, 153249);
  script_xref(name:"USN", value:"3216-2");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 : firefox regression (USN-3216-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-3216-1 fixed vulnerabilities in Firefox. The update resulted in a
startup crash when Firefox is used with XRDP. This update fixes the
problem.

We apologize for the inconvenience.

Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to bypass same origin restrictions, obtain
sensitive information, spoof the addressbar, spoof the print dialog,
cause a denial of service via application crash or hang, or execute
arbitrary code. (CVE-2017-5398, CVE-2017-5399, CVE-2017-5400,
CVE-2017-5401, CVE-2017-5402, CVE-2017-5403, CVE-2017-5404,
CVE-2017-5405, CVE-2017-5406, CVE-2017-5407, CVE-2017-5408,
CVE-2017-5410, CVE-2017-5412, CVE-2017-5413, CVE-2017-5414,
CVE-2017-5415, CVE-2017-5416, CVE-2017-5417, CVE-2017-5418,
CVE-2017-5419, CVE-2017-5420, CVE-2017-5421, CVE-2017-5422,
CVE-2017-5426, CVE-2017-5427).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017 Canonical, Inc. / NASL script (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"52.0.2+build1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"52.0.2+build1-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"firefox", pkgver:"52.0.2+build1-0ubuntu0.16.04.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"firefox", pkgver:"52.0.2+build1-0ubuntu0.16.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
