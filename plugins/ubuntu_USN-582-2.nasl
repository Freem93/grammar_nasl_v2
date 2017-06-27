#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-582-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65107);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2008-0304", "CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0415", "CVE-2008-0418", "CVE-2008-0420");
  script_osvdb_id(42057);
  script_xref(name:"USN", value:"582-2");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 : mozilla-thunderbird (USN-582-2)");
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
"USN-582-1 fixed several vulnerabilities in Thunderbird. The upstream
fixes were incomplete, and after performing certain actions
Thunderbird would crash due to memory errors. This update fixes the
problem.

We apologize for the inconvenience.

It was discovered that Thunderbird did not properly set the size of a
buffer when parsing an external-body MIME-type. If a user were to open
a specially crafted email, an attacker could cause a denial of service
via application crash or possibly execute arbitrary code as the user.
(CVE-2008-0304)

Various flaws were discovered in Thunderbird and its
JavaScript engine. By tricking a user into opening a
malicious message, an attacker could execute arbitrary code
with the user's privileges. (CVE-2008-0412, CVE-2008-0413)

Various flaws were discovered in the JavaScript engine. By
tricking a user into opening a malicious message, an
attacker could escalate privileges within Thunderbird,
perform cross-site scripting attacks and/or execute
arbitrary code with the user's privileges. (CVE-2008-0415)

Gerry Eisenhaur discovered that the chrome URI scheme did
not properly guard against directory traversal. Under
certain circumstances, an attacker may be able to load files
or steal session data. Ubuntu is not vulnerable in the
default installation. (CVE-2008-0418)

Flaws were discovered in the BMP decoder. By tricking a user
into opening a specially crafted BMP file, an attacker could
obtain sensitive information. (CVE-2008-0420).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(22, 79, 119, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-typeaheadfind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"mozilla-thunderbird", pkgver:"1.5.0.13+1.5.0.15~prepatch080227-0ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-thunderbird-dev", pkgver:"1.5.0.13+1.5.0.15~prepatch080227-0ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-thunderbird-inspector", pkgver:"1.5.0.13+1.5.0.15~prepatch080227-0ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-thunderbird-typeaheadfind", pkgver:"1.5.0.13+1.5.0.15~prepatch080227-0ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-thunderbird", pkgver:"1.5.0.13+1.5.0.15~prepatch080227-0ubuntu0.6.10.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-thunderbird-dev", pkgver:"1.5.0.13+1.5.0.15~prepatch080227-0ubuntu0.6.10.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-thunderbird-inspector", pkgver:"1.5.0.13+1.5.0.15~prepatch080227-0ubuntu0.6.10.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-thunderbird-typeaheadfind", pkgver:"1.5.0.13+1.5.0.15~prepatch080227-0ubuntu0.6.10.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-thunderbird", pkgver:"1.5.0.13+1.5.0.15~prepatch080227-0ubuntu0.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-thunderbird-dev", pkgver:"1.5.0.13+1.5.0.15~prepatch080227-0ubuntu0.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-thunderbird-inspector", pkgver:"1.5.0.13+1.5.0.15~prepatch080227-0ubuntu0.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-thunderbird-typeaheadfind", pkgver:"1.5.0.13+1.5.0.15~prepatch080227-0ubuntu0.7.04.1")) flag++;

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
