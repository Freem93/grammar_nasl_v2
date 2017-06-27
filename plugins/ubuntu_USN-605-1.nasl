#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-605-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32185);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237");
  script_osvdb_id(43857, 43858, 43859, 43860, 43861, 43862, 43863, 43864, 43865, 43866, 43867, 43868, 43869, 43870, 43871, 43872, 43873, 43874, 43875, 43876, 43877, 43878);
  script_xref(name:"USN", value:"605-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 / 8.04 LTS : mozilla-thunderbird, thunderbird vulnerabilities (USN-605-1)");
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
"Various flaws were discovered in the JavaScript engine. If a user had
JavaScript enabled and were tricked into opening a malicious email, an
attacker could escalate privileges within Thunderbird, perform
cross-site scripting attacks and/or execute arbitrary code with the
user's privileges. (CVE-2008-1233, CVE-2008-1234, CVE-2008-1235)

Several problems were discovered in Thunderbird which could lead to
crashes and memory corruption. If a user had JavaScript enabled and
were tricked into opening a malicious email, an attacker may be able
to execute arbitrary code with the user's privileges. (CVE-2008-1236,
CVE-2008-1237).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 94, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-typeaheadfind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-gnome-support");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.04|7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.04 / 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"mozilla-thunderbird", pkgver:"1.5.0.13+1.5.0.15~prepatch080417a-0ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-thunderbird-dev", pkgver:"1.5.0.13+1.5.0.15~prepatch080417a-0ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-thunderbird-inspector", pkgver:"1.5.0.13+1.5.0.15~prepatch080417a-0ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-thunderbird-typeaheadfind", pkgver:"1.5.0.13+1.5.0.15~prepatch080417a-0ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-thunderbird", pkgver:"1.5.0.13+1.5.0.15~prepatch080417a-0ubuntu0.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-thunderbird-dev", pkgver:"1.5.0.13+1.5.0.15~prepatch080417a-0ubuntu0.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-thunderbird-inspector", pkgver:"1.5.0.13+1.5.0.15~prepatch080417a-0ubuntu0.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-thunderbird-typeaheadfind", pkgver:"1.5.0.13+1.5.0.15~prepatch080417a-0ubuntu0.7.04.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.14+nobinonly-0ubuntu0.7.10.0")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mozilla-thunderbird-dev", pkgver:"2.0.0.14+nobinonly-0ubuntu0.7.10.0")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"thunderbird", pkgver:"2.0.0.14+nobinonly-0ubuntu0.7.10.0")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"thunderbird-dev", pkgver:"2.0.0.14+nobinonly-0ubuntu0.7.10.0")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"thunderbird-gnome-support", pkgver:"2.0.0.14+nobinonly-0ubuntu0.7.10.0")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.14+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mozilla-thunderbird-dev", pkgver:"2.0.0.14+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"thunderbird", pkgver:"2.0.0.14+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"thunderbird-dev", pkgver:"2.0.0.14+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"thunderbird-gnome-support", pkgver:"2.0.0.14+nobinonly-0ubuntu0.8.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-thunderbird / mozilla-thunderbird-dev / etc");
}
