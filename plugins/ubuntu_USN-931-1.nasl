#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-931-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45575);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/01 21:21:53 $");

  script_cve_id("CVE-2009-4632", "CVE-2009-4633", "CVE-2009-4634", "CVE-2009-4635", "CVE-2009-4637", "CVE-2009-4638", "CVE-2009-4639", "CVE-2009-4640");
  script_bugtraq_id(36465);
  script_osvdb_id(58504, 58505, 58506, 58507, 58509, 58510, 62327, 62328);
  script_xref(name:"USN", value:"931-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 / 9.10 : ffmpeg, ffmpeg-debian vulnerabilities (USN-931-1)");
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
"It was discovered that FFmpeg contained multiple security issues when
handling certain multimedia files. If a user were tricked into opening
a crafted multimedia file, an attacker could cause a denial of service
via application crash, or possibly execute arbitrary code with the
privileges of the user invoking the program.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ffmpeg-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ffmpeg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec1d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter0");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/20");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"ffmpeg", pkgver:"0.cvs20070307-5ubuntu7.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavcodec-dev", pkgver:"0.cvs20070307-5ubuntu7.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavcodec1d", pkgver:"3:0.cvs20070307-5ubuntu7.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavformat-dev", pkgver:"0.cvs20070307-5ubuntu7.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavformat1d", pkgver:"3:0.cvs20070307-5ubuntu7.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavutil-dev", pkgver:"0.cvs20070307-5ubuntu7.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libavutil1d", pkgver:"0.cvs20070307-5ubuntu7.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpostproc-dev", pkgver:"0.cvs20070307-5ubuntu7.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpostproc1d", pkgver:"0.cvs20070307-5ubuntu7.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libswscale-dev", pkgver:"0.cvs20070307-5ubuntu7.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libswscale1d", pkgver:"0.cvs20070307-5ubuntu7.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ffmpeg", pkgver:"0.svn20080206-12ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ffmpeg-dbg", pkgver:"0.svn20080206-12ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ffmpeg-doc", pkgver:"0.svn20080206-12ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavcodec-dev", pkgver:"0.svn20080206-12ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavcodec51", pkgver:"3:0.svn20080206-12ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavdevice-dev", pkgver:"0.svn20080206-12ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavdevice52", pkgver:"0.svn20080206-12ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavformat-dev", pkgver:"0.svn20080206-12ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavformat52", pkgver:"3:0.svn20080206-12ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavutil-dev", pkgver:"0.svn20080206-12ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libavutil49", pkgver:"0.svn20080206-12ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpostproc-dev", pkgver:"0.svn20080206-12ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpostproc51", pkgver:"0.svn20080206-12ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libswscale-dev", pkgver:"0.svn20080206-12ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libswscale0", pkgver:"0.svn20080206-12ubuntu3.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ffmpeg", pkgver:"0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ffmpeg-dbg", pkgver:"0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ffmpeg-doc", pkgver:"0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libavcodec-dev", pkgver:"0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libavcodec52", pkgver:"3:0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libavdevice-dev", pkgver:"0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libavdevice52", pkgver:"0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libavfilter-dev", pkgver:"0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libavfilter0", pkgver:"0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libavformat-dev", pkgver:"0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libavformat52", pkgver:"3:0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libavutil-dev", pkgver:"0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libavutil49", pkgver:"0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpostproc-dev", pkgver:"0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpostproc51", pkgver:"0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libswscale-dev", pkgver:"0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libswscale0", pkgver:"0.svn20090303-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ffmpeg", pkgver:"0.5+svn20090706-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ffmpeg-dbg", pkgver:"0.5+svn20090706-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ffmpeg-doc", pkgver:"0.5+svn20090706-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavcodec-dev", pkgver:"0.5+svn20090706-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavcodec52", pkgver:"4:0.5+svn20090706-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavdevice-dev", pkgver:"0.5+svn20090706-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavdevice52", pkgver:"0.5+svn20090706-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavfilter-dev", pkgver:"0.5+svn20090706-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavfilter0", pkgver:"0.5+svn20090706-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavformat-dev", pkgver:"0.5+svn20090706-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavformat52", pkgver:"4:0.5+svn20090706-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavutil-dev", pkgver:"0.5+svn20090706-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libavutil49", pkgver:"0.5+svn20090706-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpostproc-dev", pkgver:"0.5+svn20090706-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpostproc51", pkgver:"0.5+svn20090706-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libswscale-dev", pkgver:"0.5+svn20090706-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libswscale0", pkgver:"0.5+svn20090706-2ubuntu2.1")) flag++;

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
