#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-149-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20546);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/27 14:21:16 $");

  script_cve_id("CVE-2004-1156", "CVE-2004-1381", "CVE-2005-0141", "CVE-2005-0142", "CVE-2005-0143", "CVE-2005-0144", "CVE-2005-0145", "CVE-2005-0146", "CVE-2005-0147", "CVE-2005-0150", "CVE-2005-0230", "CVE-2005-0231", "CVE-2005-0232", "CVE-2005-0233", "CVE-2005-0255", "CVE-2005-0399", "CVE-2005-0401", "CVE-2005-0402", "CVE-2005-0578", "CVE-2005-0584", "CVE-2005-0585", "CVE-2005-0586", "CVE-2005-0587", "CVE-2005-0588", "CVE-2005-0589", "CVE-2005-0590", "CVE-2005-0591", "CVE-2005-0592", "CVE-2005-0593", "CVE-2005-0752", "CVE-2005-0989", "CVE-2005-1153", "CVE-2005-1154", "CVE-2005-1155", "CVE-2005-1156", "CVE-2005-1157", "CVE-2005-1158", "CVE-2005-1159", "CVE-2005-1160", "CVE-2005-1531", "CVE-2005-1532", "CVE-2005-1937", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2262", "CVE-2005-2263", "CVE-2005-2264", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270");
  script_xref(name:"USN", value:"149-3");

  script_name(english:"Ubuntu 4.10 : mozilla-firefox vulnerabilities (USN-149-3)");
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
"USN-149-1 fixed some vulnerabilities in the Ubuntu 5.04 (Hoary
Hedgehog) version of Firefox. The version shipped with Ubuntu 4.10
(Warty Warthog) is also vulnerable to these flaws, so it needs to be
upgraded as well. Please see

http://www.ubuntulinux.org/support/documentation/usn/usn-149-1

for the original advisory.

This update also fixes several older vulnerabilities; Some of them
could be exploited to execute arbitrary code with full user privileges
if the user visited a malicious website. (MFSA-2005-01 to
MFSA-2005-44; please see the following website for details:
http://www.mozilla.org/projects/security/known-vulnerabilities.html)

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox compareTo() Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-locale-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-locale-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-locale-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-locale-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-locale-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-locale-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-locale-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-locale-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-locale-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-locale-uk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox", pkgver:"1.0.6-0ubuntu0.0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox-dom-inspector", pkgver:"1.0.6-0ubuntu0.0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox-locale-ca", pkgver:"1.0-0ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox-locale-de", pkgver:"1.0-0ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox-locale-es", pkgver:"1.0-0ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox-locale-fr", pkgver:"1.0-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox-locale-it", pkgver:"1.0-0ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox-locale-ja", pkgver:"1.0-0ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox-locale-nb", pkgver:"1.0-0ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox-locale-pl", pkgver:"1.0-0ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox-locale-tr", pkgver:"1.0-0ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-firefox-locale-uk", pkgver:"1.0-0ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-firefox / mozilla-firefox-dom-inspector / etc");
}
