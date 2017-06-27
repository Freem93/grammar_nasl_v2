#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-734-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38037);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-4610", "CVE-2008-4866", "CVE-2008-4867", "CVE-2009-0385");
  script_bugtraq_id(33502);
  script_xref(name:"USN", value:"734-1");

  script_name(english:"Ubuntu 7.10 / 8.04 LTS / 8.10 : ffmpeg, ffmpeg-debian vulnerabilities (USN-734-1)");
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
"It was discovered that FFmpeg did not correctly handle certain
malformed Ogg Media (OGM) files. If a user were tricked into opening a
crafted Ogg Media file, an attacker could cause the application using
FFmpeg to crash, leading to a denial of service. (CVE-2008-4610)

It was discovered that FFmpeg did not correctly handle certain
parameters when creating DTS streams. If a user were tricked into
processing certain commands, an attacker could cause a denial of
service via application crash, or possibly execute arbitrary code with
the privileges of the user invoking the program. This issue only
affected Ubuntu 8.10. (CVE-2008-4866)

It was discovered that FFmpeg did not correctly handle certain
malformed DTS Coherent Acoustics (DCA) files. If a user were tricked
into opening a crafted DCA file, an attacker could cause a denial of
service via application crash, or possibly execute arbitrary code with
the privileges of the user invoking the program. (CVE-2008-4867)

It was discovered that FFmpeg did not correctly handle certain
malformed 4X movie (4xm) files. If a user were tricked into opening a
crafted 4xm file, an attacker could execute arbitrary code with the
privileges of the user invoking the program. (CVE-2009-0385).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ffmpeg-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ffmpeg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec1d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat1d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil1d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil49");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc1d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale1d");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/16");
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
if (! ereg(pattern:"^(7\.10|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 7.10 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"7.10", pkgname:"ffmpeg", pkgver:"0.cvs20070307-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavcodec-dev", pkgver:"0.cvs20070307-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavcodec1d", pkgver:"3:0.cvs20070307-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavformat-dev", pkgver:"0.cvs20070307-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavformat1d", pkgver:"3:0.cvs20070307-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavutil-dev", pkgver:"0.cvs20070307-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libavutil1d", pkgver:"0.cvs20070307-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpostproc-dev", pkgver:"0.cvs20070307-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libpostproc1d", pkgver:"0.cvs20070307-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libswscale-dev", pkgver:"0.cvs20070307-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libswscale1d", pkgver:"0.cvs20070307-5ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ffmpeg", pkgver:"0.cvs20070307-5ubuntu7.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavcodec-dev", pkgver:"0.cvs20070307-5ubuntu7.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavcodec1d", pkgver:"3:0.cvs20070307-5ubuntu7.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavformat-dev", pkgver:"0.cvs20070307-5ubuntu7.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavformat1d", pkgver:"3:0.cvs20070307-5ubuntu7.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavutil-dev", pkgver:"0.cvs20070307-5ubuntu7.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavutil1d", pkgver:"0.cvs20070307-5ubuntu7.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpostproc-dev", pkgver:"0.cvs20070307-5ubuntu7.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpostproc1d", pkgver:"0.cvs20070307-5ubuntu7.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libswscale-dev", pkgver:"0.cvs20070307-5ubuntu7.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libswscale1d", pkgver:"0.cvs20070307-5ubuntu7.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ffmpeg", pkgver:"0.svn20080206-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ffmpeg-dbg", pkgver:"0.svn20080206-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ffmpeg-doc", pkgver:"0.svn20080206-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavcodec-dev", pkgver:"0.svn20080206-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavcodec51", pkgver:"3:0.svn20080206-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavdevice-dev", pkgver:"0.svn20080206-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavdevice52", pkgver:"0.svn20080206-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavformat-dev", pkgver:"0.svn20080206-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavformat52", pkgver:"3:0.svn20080206-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavutil-dev", pkgver:"0.svn20080206-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavutil49", pkgver:"0.svn20080206-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpostproc-dev", pkgver:"0.svn20080206-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpostproc51", pkgver:"0.svn20080206-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libswscale-dev", pkgver:"0.svn20080206-12ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libswscale0", pkgver:"0.svn20080206-12ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ffmpeg / ffmpeg-dbg / ffmpeg-doc / libavcodec-dev / libavcodec1d / etc");
}
