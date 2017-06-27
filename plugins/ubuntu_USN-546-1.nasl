#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-546-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28358);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");
  script_osvdb_id(38463, 38867, 38868);
  script_xref(name:"USN", value:"546-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : firefox vulnerabilities (USN-546-1)");
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
"It was discovered that Firefox incorrectly associated redirected sites
as the origin of 'jar:' contents. A malicious website could exploit
this to modify or steal confidential data (such as passwords) from
other web sites. (CVE-2007-5947)

Various flaws were discovered in the layout and JavaScript engines. By
tricking a user into opening a malicious web page, an attacker could
execute arbitrary code with the user's privileges. (CVE-2007-5959)

Gregory Fleischer discovered that it was possible to use JavaScript to
manipulate Firefox's Referer header. A malicious website could exploit
this to conduct cross-site request forgeries against sites that relied
only on Referer headers for protection from such attacks.
(CVE-2007-5960).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-libthai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"firefox", pkgver:"1.5.dfsg+1.5.0.14~prepatch071125a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dbg", pkgver:"1.5.dfsg+1.5.0.14~prepatch071125a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dev", pkgver:"1.5.dfsg+1.5.0.14~prepatch071125a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-dom-inspector", pkgver:"1.5.dfsg+1.5.0.14~prepatch071125a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"firefox-gnome-support", pkgver:"1.5.dfsg+1.5.0.14~prepatch071125a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnspr-dev", pkgver:"1.firefox1.5.dfsg+1.5.0.14~prepatch071125a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnspr4", pkgver:"1.firefox1.5.dfsg+1.5.0.14~prepatch071125a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnss-dev", pkgver:"1.firefox1.5.dfsg+1.5.0.14~prepatch071125a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libnss3", pkgver:"1.firefox1.5.dfsg+1.5.0.14~prepatch071125a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-firefox", pkgver:"1.5.dfsg+1.5.0.14~prepatch071125a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-firefox-dev", pkgver:"1.5.dfsg+1.5.0.14~prepatch071125a-0ubuntu1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox", pkgver:"2.0.0.10+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox-dbg", pkgver:"2.0.0.10+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox-dev", pkgver:"2.0.0.10+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox-dom-inspector", pkgver:"2.0.0.10+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"firefox-gnome-support", pkgver:"2.0.0.10+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libnspr-dev", pkgver:"1.firefox2.0.0.10+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libnspr4", pkgver:"1.firefox2.0.0.10+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libnss-dev", pkgver:"1.firefox2.0.0.10+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libnss3", pkgver:"1.firefox2.0.0.10+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-firefox", pkgver:"2.0.0.10+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-firefox-dev", pkgver:"2.0.0.10+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-firefox-dom-inspector", pkgver:"2.0.0.10+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-firefox-gnome-support", pkgver:"2.0.0.10+0nobinonly-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox", pkgver:"2.0.0.10+1nobinonly-0ubuntu1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-dbg", pkgver:"2.0.0.10+1nobinonly-0ubuntu1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-dev", pkgver:"2.0.0.10+1nobinonly-0ubuntu1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-dom-inspector", pkgver:"2.0.0.10+1nobinonly-0ubuntu1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-gnome-support", pkgver:"2.0.0.10+1nobinonly-0ubuntu1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"firefox-libthai", pkgver:"2.0.0.10+1nobinonly-0ubuntu1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libnspr-dev", pkgver:"1.firefox2.0.0.10+1nobinonly-0ubuntu1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libnspr4", pkgver:"1.firefox2.0.0.10+1nobinonly-0ubuntu1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libnss-dev", pkgver:"1.firefox2.0.0.10+1nobinonly-0ubuntu1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libnss3", pkgver:"1.firefox2.0.0.10+1nobinonly-0ubuntu1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-firefox", pkgver:"2.0.0.10+1nobinonly-0ubuntu1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-firefox-dev", pkgver:"2.0.0.10+1nobinonly-0ubuntu1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-firefox-dom-inspector", pkgver:"2.0.0.10+1nobinonly-0ubuntu1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-firefox-gnome-support", pkgver:"2.0.0.10+1nobinonly-0ubuntu1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox", pkgver:"2.0.0.10+2nobinonly-0ubuntu1.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-dbg", pkgver:"2.0.0.10+2nobinonly-0ubuntu1.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-dev", pkgver:"2.0.0.10+2nobinonly-0ubuntu1.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-dom-inspector", pkgver:"2.0.0.10+2nobinonly-0ubuntu1.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-gnome-support", pkgver:"2.0.0.10+2nobinonly-0ubuntu1.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"firefox-libthai", pkgver:"2.0.0.10+2nobinonly-0ubuntu1.7.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-dbg / firefox-dev / firefox-dom-inspector / etc");
}
