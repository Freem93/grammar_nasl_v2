#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-930-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47574);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2008-5913", "CVE-2010-1121", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202", "CVE-2010-1203");
  script_xref(name:"USN", value:"930-3");

  script_name(english:"Ubuntu 8.04 LTS : firefox regression (USN-930-3)");
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
"USN-930-1 fixed vulnerabilities in Firefox. Due to a software
packaging problem, the Firefox 3.6 update could not be installed when
the firefox-2 package was also installed. This update fixes the
problem and updates apturl for the change.

If was discovered that Firefox could be made to access freed memory.
If a user were tricked into viewing a malicious site, a remote
attacker could cause a denial of service or possibly execute arbitrary
code with the privileges of the user invoking the program. This issue
only affected Ubuntu 8.04 LTS. (CVE-2010-1121)

Several flaws were discovered in the browser engine of
Firefox. If a user were tricked into viewing a malicious
site, a remote attacker could cause a denial of service or
possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2010-1200, CVE-2010-1201,
CVE-2010-1202, CVE-2010-1203)

A flaw was discovered in the way plugin instances
interacted. An attacker could potentially exploit this and
use one plugin to access freed memory from a second plugin
to execute arbitrary code with the privileges of the user
invoking the program. (CVE-2010-1198)

An integer overflow was discovered in Firefox. If a user
were tricked into viewing a malicious site, an attacker
could overflow a buffer and cause a denial of service or
possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2010-1196)

Martin Barbella discovered an integer overflow in an XSLT
node sorting routine. An attacker could exploit this to
overflow a buffer and cause a denial of service or possibly
execute arbitrary code with the privileges of the user
invoking the program. (CVE-2010-1199)

Michal Zalewski discovered that the focus behavior of
Firefox could be subverted. If a user were tricked into
viewing a malicious site, a remote attacker could use this
to capture keystrokes. (CVE-2010-1125)

Ilja van Sprundel discovered that the 'Content-Disposition:
attachment' HTTP header was ignored when 'Content-Type:
multipart' was also present. Under certain circumstances,
this could potentially lead to cross-site scripting attacks.
(CVE-2010-1197)

Amit Klein discovered that Firefox did not seed its random
number generator often enough. An attacker could exploit
this to identify and track users across different websites.
(CVE-2008-5913).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:abrowser-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apturl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-3.0-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-gnome-support-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-granparadiso-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-libthai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-trunk-gnome-support");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
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
if (! ereg(pattern:"^(8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"abrowser", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"abrowser-branding", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apturl", pkgver:"0.2.2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0-dev", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-3.0-gnome-support", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-branding", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-dbg", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-dev", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-gnome-support", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-gnome-support-dbg", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso-dev", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-granparadiso-gnome-support", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-libthai", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk-dev", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"firefox-trunk-gnome-support", pkgver:"3.6.6+nobinonly-0ubuntu0.8.04.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abrowser / abrowser-branding / apturl / firefox / firefox-3.0 / etc");
}
