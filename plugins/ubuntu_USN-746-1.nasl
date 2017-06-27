#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-746-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37983);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-5239", "CVE-2009-0698");
  script_bugtraq_id(33502);
  script_xref(name:"USN", value:"746-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : xine-lib vulnerability (USN-746-1)");
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
"It was discovered that the 4xm demuxer in xine-lib did not correctly
handle a large current_track value in a 4xm file, resulting in an
integer overflow. If a user or automated system were tricked into
opening a specially crafted 4xm movie file, an attacker could crash
xine-lib or possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2009-0698)

USN-710-1 provided updated xine-lib packages to fix multiple security
vulnerabilities. The security patch to fix CVE-2008-5239 introduced a
regression causing some media files to be unplayable. This update
corrects the problem. We apologize for the inconvenience.

It was discovered that the input handlers in xine-lib did not
correctly handle certain error codes, resulting in out-of-bounds reads
and heap- based buffer overflows. If a user or automated system were
tricked into opening a specially crafted file, stream, or URL, an
attacker could execute arbitrary code as the user invoking the
program. (CVE-2008-5239).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine-main1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-all-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-misc-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.10|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.10 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libxine-dev", pkgver:"1.1.1+ubuntu2-7.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxine-main1", pkgver:"1.1.1+ubuntu2-7.11")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine-dev", pkgver:"1.1.7-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1", pkgver:"1.1.7-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-console", pkgver:"1.1.7-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-dbg", pkgver:"1.1.7-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-doc", pkgver:"1.1.7-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-ffmpeg", pkgver:"1.1.7-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-gnome", pkgver:"1.1.7-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-plugins", pkgver:"1.1.7-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine-dev", pkgver:"1.1.11.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1", pkgver:"1.1.11.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-all-plugins", pkgver:"1.1.11.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-bin", pkgver:"1.1.11.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-console", pkgver:"1.1.11.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-dbg", pkgver:"1.1.11.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-doc", pkgver:"1.1.11.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-ffmpeg", pkgver:"1.1.11.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-gnome", pkgver:"1.1.11.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-misc-plugins", pkgver:"1.1.11.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-plugins", pkgver:"1.1.11.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-x", pkgver:"1.1.11.1-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine-dev", pkgver:"1.1.15-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1", pkgver:"1.1.15-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-all-plugins", pkgver:"1.1.15-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-bin", pkgver:"1.1.15-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-console", pkgver:"1.1.15-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-dbg", pkgver:"1.1.15-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-doc", pkgver:"1.1.15-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-ffmpeg", pkgver:"1.1.15-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-gnome", pkgver:"1.1.15-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-misc-plugins", pkgver:"1.1.15-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-plugins", pkgver:"1.1.15-0ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-x", pkgver:"1.1.15-0ubuntu3.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxine-dev / libxine-main1 / libxine1 / libxine1-all-plugins / etc");
}
