#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-536-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28142);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2006-2894", "CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340");
  script_bugtraq_id(18308, 22688, 23668, 24725, 26132);
  script_xref(name:"USN", value:"536-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : mozilla-thunderbird, thunderbird vulnerabilities (USN-536-1)");
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
"Various flaws were discovered in the layout and JavaScript engines. By
tricking a user into opening a malicious web page, an attacker could
execute arbitrary code with the user's privileges. (CVE-2007-5339,
CVE-2007-5340)

Flaws were discovered in the file upload form control. By tricking a
user into opening a malicious web page, an attacker could force
arbitrary files from the user's computer to be uploaded without their
consent. (CVE-2006-2894, CVE-2007-3511)

Michal Zalewski discovered that the onUnload event handlers were
incorrectly able to access information outside the old page content. A
malicious website could exploit this to modify the contents, or steal
confidential data (such as passwords), of the next loaded web page.
(CVE-2007-1095)

Stefano Di Paola discovered that Thunderbird did not correctly request
Digest Authentications. A malicious website could exploit this to
inject arbitrary HTTP headers or perform session splitting attacks
against proxies. (CVE-2007-2292)

Eli Friedman discovered that XUL could be used to hide a window's
titlebar. A malicious website could exploit this to enhance their
attempts at creating phishing websites. (CVE-2007-5334)

Georgi Guninski discovered that Thunderbird would allow file-system
based web pages to access additional files. By tricking a user into
opening a malicious web page from a gnome-vfs location, an attacker
could steal arbitrary files from the user's computer. (CVE-2007-5337)

It was discovered that the XPCNativeWrappers were not safe in certain
situations. By tricking a user into opening a malicious web page, an
attacker could run arbitrary JavaScript with the user's privileges.
(CVE-2007-5338)

Please note that JavaScript is disabled by default for emails, and it
is not recommended to enable it.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 20, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-typeaheadfind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-gnome-support");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
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

if (ubuntu_check(osver:"6.06", pkgname:"mozilla-thunderbird", pkgver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-thunderbird-dev", pkgver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-thunderbird-inspector", pkgver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"mozilla-thunderbird-typeaheadfind", pkgver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.06")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-thunderbird", pkgver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-thunderbird-dev", pkgver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-thunderbird-inspector", pkgver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"mozilla-thunderbird-typeaheadfind", pkgver:"1.5.0.13+1.5.0.14b-0ubuntu0.6.10")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-thunderbird", pkgver:"1.5.0.13+1.5.0.14b-0ubuntu0.7.04")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-thunderbird-dev", pkgver:"1.5.0.13+1.5.0.14b-0ubuntu0.7.04")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-thunderbird-inspector", pkgver:"1.5.0.13+1.5.0.14b-0ubuntu0.7.04")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"mozilla-thunderbird-typeaheadfind", pkgver:"1.5.0.13+1.5.0.14b-0ubuntu0.7.04")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.8~pre071022+nobinonly-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"mozilla-thunderbird-dev", pkgver:"2.0.0.8~pre071022+nobinonly-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"thunderbird", pkgver:"2.0.0.8~pre071022+nobinonly-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"thunderbird-dev", pkgver:"2.0.0.8~pre071022+nobinonly-0ubuntu0.7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"thunderbird-gnome-support", pkgver:"2.0.0.8~pre071022+nobinonly-0ubuntu0.7.10")) flag++;

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
