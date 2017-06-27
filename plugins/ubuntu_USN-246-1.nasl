#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-246-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21054);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/09 14:23:24 $");

  script_cve_id("CVE-2005-4601", "CVE-2006-0082");
  script_bugtraq_id(16093);
  script_osvdb_id(22121, 22671);
  script_xref(name:"USN", value:"246-1");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : imagemagick vulnerabilities (USN-246-1)");
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
"Florian Weimer discovered that the delegate code did not correctly
handle file names which embed shell commands (CVE-2005-4601). Daniel
Kobras found a format string vulnerability in the SetImageInfo()
function (CVE-2006-0082). By tricking a user into processing an image
file with a specially crafted file name, these two vulnerabilities
could be exploited to execute arbitrary commands with the user's
privileges. These vulnerability become particularly critical if
malicious images are sent as email attachments and the email client
uses imagemagick to convert/display the images (e. g. Thunderbird and
Gnus).

In addition, Eero Hakkinen reported a bug in the command line argument
processing of the 'display' command. Arguments that contained
wildcards and were expanded to several files could trigger a heap
overflow. However, there is no known possiblity to exploit this
remotely. (http://bugs.debian.org/345595)

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++6c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"imagemagick", pkgver:"6.0.2.5-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libmagick++6", pkgver:"6.0.2.5-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libmagick++6-dev", pkgver:"6.0.2.5-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libmagick6", pkgver:"6.0.2.5-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libmagick6-dev", pkgver:"6.0.2.5-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"perlmagick", pkgver:"6.0.2.5-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"imagemagick", pkgver:"6.0.6.2-2.1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmagick++6", pkgver:"6.0.6.2-2.1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmagick++6-dev", pkgver:"6.0.6.2-2.1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmagick6", pkgver:"6.0.6.2-2.1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmagick6-dev", pkgver:"6.0.6.2-2.1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"perlmagick", pkgver:"6.0.6.2-2.1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"imagemagick", pkgver:"6.2.3.4-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmagick++6-dev", pkgver:"6.2.3.4-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmagick++6c2", pkgver:"6.2.3.4-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmagick6", pkgver:"6.2.3.4-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmagick6-dev", pkgver:"6.2.3.4-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"perlmagick", pkgver:"6.2.3.4-1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imagemagick / libmagick++6 / libmagick++6-dev / libmagick++6c2 / etc");
}