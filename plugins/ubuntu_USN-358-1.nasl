#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-358-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27938);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:21:17 $");

  script_cve_id("CVE-2006-4799", "CVE-2006-4800");
  script_osvdb_id(29312, 29553);
  script_xref(name:"USN", value:"358-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : ffmpeg, xine-lib vulnerabilities (USN-358-1)");
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
"XFOCUS Security Team discovered that the AVI decoder used in xine-lib
did not correctly validate certain headers. By tricking a user into
playing an AVI with malicious headers, an attacker could execute
arbitrary code with the target user's privileges. (CVE-2006-4799)

Multiple integer overflows were discovered in ffmpeg and tools that
contain a copy of ffmpeg (like xine-lib and kino), for several types
of video formats. By tricking a user into running a video player that
uses ffmpeg on a stream with malicious content, an attacker could
execute arbitrary code with the target user's privileges.
(CVE-2006-4800).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine-main1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1c2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.04|5\.10|6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10 / 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"ffmpeg", pkgver:"0.cvs20050121-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kino", pkgver:"0.75-6ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libavcodec-dev", pkgver:"3:0.cvs20050121-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libavformat-dev", pkgver:"0.cvs20050121-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libpostproc-dev", pkgver:"0.cvs20050121-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxine-dev", pkgver:"1.0-1ubuntu3.9")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxine1", pkgver:"1.0-1ubuntu3.9")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ffmpeg", pkgver:"0.cvs20050918-4ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libavcodec-dev", pkgver:"3:0.cvs20050918-4ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libavformat-dev", pkgver:"0.cvs20050918-4ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpostproc-dev", pkgver:"0.cvs20050918-4ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libxine-dev", pkgver:"1.0.1-1ubuntu10.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libxine1c2", pkgver:"1.0.1-1ubuntu10.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ffmpeg", pkgver:"0.cvs20050918-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavcodec-dev", pkgver:"3:0.cvs20050918-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libavformat-dev", pkgver:"0.cvs20050918-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpostproc-dev", pkgver:"0.cvs20050918-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxine-dev", pkgver:"1.1.1+ubuntu2-7.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxine-main1", pkgver:"1.1.1+ubuntu2-7.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ffmpeg / kino / libavcodec-dev / libavformat-dev / libpostproc-dev / etc");
}
