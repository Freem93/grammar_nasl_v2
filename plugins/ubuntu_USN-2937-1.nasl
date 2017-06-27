#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2937-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90094);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/05/24 17:52:29 $");

  script_cve_id("CVE-2014-1748", "CVE-2015-1071", "CVE-2015-1076", "CVE-2015-1081", "CVE-2015-1083", "CVE-2015-1120", "CVE-2015-1122", "CVE-2015-1127", "CVE-2015-1153", "CVE-2015-1155", "CVE-2015-3658", "CVE-2015-3659", "CVE-2015-3727", "CVE-2015-3731", "CVE-2015-3741", "CVE-2015-3743", "CVE-2015-3745", "CVE-2015-3747", "CVE-2015-3748", "CVE-2015-3749", "CVE-2015-3752", "CVE-2015-5788", "CVE-2015-5794", "CVE-2015-5801", "CVE-2015-5809", "CVE-2015-5822", "CVE-2015-5928");
  script_osvdb_id(107144, 119676, 119681, 119686, 119690, 119691, 120403, 120405, 121739, 121741, 123914, 123917, 123918, 126106, 126116, 126118, 126120, 126122, 126123, 126124, 126127, 127617, 127655, 127661, 127668, 127683, 129215);
  script_xref(name:"USN", value:"2937-1");

  script_name(english:"Ubuntu 14.04 LTS / 15.10 : webkitgtk vulnerabilities (USN-2937-1)");
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
"A large number of security issues were discovered in the WebKitGTK+
Web and JavaScript engines. If a user were tricked into viewing a
malicious website, a remote attacker could exploit a variety of issues
related to web browser security, including cross-site scripting
attacks, denial of service attacks, and arbitrary code execution.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjavascriptcoregtk-3.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkitgtk-1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebkitgtk-3.0-0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"libjavascriptcoregtk-1.0-0", pkgver:"2.4.10-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libjavascriptcoregtk-3.0-0", pkgver:"2.4.10-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libwebkitgtk-1.0-0", pkgver:"2.4.10-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libwebkitgtk-3.0-0", pkgver:"2.4.10-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libjavascriptcoregtk-1.0-0", pkgver:"2.4.10-0ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libjavascriptcoregtk-3.0-0", pkgver:"2.4.10-0ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libwebkitgtk-1.0-0", pkgver:"2.4.10-0ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libwebkitgtk-3.0-0", pkgver:"2.4.10-0ubuntu0.15.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjavascriptcoregtk-1.0-0 / libjavascriptcoregtk-3.0-0 / etc");
}
