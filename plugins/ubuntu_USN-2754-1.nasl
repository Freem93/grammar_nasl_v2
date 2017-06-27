#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2754-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86293);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/24 17:44:51 $");

  script_cve_id("CVE-2015-4500", "CVE-2015-4506", "CVE-2015-4509", "CVE-2015-4511", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7180");
  script_xref(name:"USN", value:"2754-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.04 : thunderbird vulnerabilities (USN-2754-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Andrew Osmond, Olli Pettay, Andrew Sutherland, Christian Holler, David
Major, Andrew McCreight, and Cameron McCormack discovered multiple
memory safety issues in Thunderbird. If a user were tricked in to
opening a specially crafted message, an attacker could potentially
exploit these to cause a denial of service via application crash, or
execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2015-4500)

Khalil Zhani discovered a buffer overflow when parsing VP9 content in
some circumstances. If a user were tricked in to opening a specially
crafted message, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code
with the privileges of the user invoking Thunderbird. (CVE-2015-4506)

A use-after-free was discovered when manipulating HTML media content
in some circumstances. If a user were tricked in to opening a
specially crafted website in a browsing context, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user
invoking Thunderbird. (CVE-2015-4509)

Atte Kettunen discovered a buffer overflow in the nestegg library when
decoding WebM format video in some circumstances. If a user were
tricked in to opening a specially crafted message, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user
invoking Thunderbird. (CVE-2015-4511)

Ronald Crane reported multiple vulnerabilities. If a user were tricked
in to opening a specially crafted website in a browsing context, an
attacker could potentially exploit these to cause a denial of service
via application crash, or execute arbitrary code with the privileges
of the user invoking Thunderbird. (CVE-2015-4517, CVE-2015-4521,
CVE-2015-4522, CVE-2015-7174, CVE-2015-7175, CVE-2015-7176,
CVE-2015-7177, CVE-2015-7180)

Mario Gomes discovered that dragging and dropping an image after a
redirect exposes the redirected URL to scripts. An attacker could
potentially exploit this to obtain sensitive information.
(CVE-2015-4519)

Ehsan Akhgari discovered 2 issues with CORS preflight requests. An
attacker could potentially exploit these to bypass CORS restrictions.
(CVE-2015-4520).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"thunderbird", pkgver:"1:38.3.0+build1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"thunderbird", pkgver:"1:38.3.0+build1-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"thunderbird", pkgver:"1:38.3.0+build1-0ubuntu0.15.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
