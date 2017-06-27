#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-710-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37469);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-3231", "CVE-2008-5233", "CVE-2008-5234", "CVE-2008-5236", "CVE-2008-5237", "CVE-2008-5238", "CVE-2008-5239", "CVE-2008-5240", "CVE-2008-5241", "CVE-2008-5242", "CVE-2008-5243", "CVE-2008-5244", "CVE-2008-5246", "CVE-2008-5248");
  script_bugtraq_id(30698, 30699, 30797);
  script_xref(name:"USN", value:"710-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : xine-lib vulnerabilities (USN-710-1)");
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
"It was discovered that xine-lib did not correctly handle certain
malformed Ogg and Windows Media files. If a user or automated system
were tricked into opening a specially crafted Ogg or Windows Media
file, an attacker could cause xine-lib to crash, creating a denial of
service. This issue only applied to Ubuntu 6.06 LTS, 7.10, and 8.04
LTS. (CVE-2008-3231)

It was discovered that the MNG, MOD, and Real demuxers in xine-lib did
not correctly handle memory allocation failures. If a user or
automated system were tricked into opening a specially crafted MNG,
MOD, or Real file, an attacker could crash xine-lib or possibly
execute arbitrary code with the privileges of the user invoking the
program. This issue only applied to Ubuntu 6.06 LTS, 7.10, and 8.04
LTS. (CVE-2008-5233)

It was discovered that the QT demuxer in xine-lib did not correctly
handle an invalid metadata atom size, resulting in a heap-based buffer
overflow. If a user or automated system were tricked into opening a
specially crafted MOV file, an attacker could execute arbitrary code
as the user invoking the program. (CVE-2008-5234, CVE-2008-5242)

It was discovered that the Real, RealAudio, and Matroska demuxers in
xine-lib did not correctly handle malformed files, resulting in
heap-based buffer overflows. If a user or automated system were
tricked into opening a specially crafted Real, RealAudio, or Matroska
file, an attacker could execute arbitrary code as the user invoking
the program. (CVE-2008-5236)

It was discovered that the MNG and QT demuxers in xine-lib did not
correctly handle malformed files, resulting in integer overflows. If a
user or automated system were tricked into opening a specially crafted
MNG or MOV file, an attacker could execute arbitrary code as the user
invoking the program. (CVE-2008-5237)

It was discovered that the Matroska, MOD, Real, and Real Audio
demuxers in xine-lib did not correctly handle malformed files,
resulting in integer overflows. If a user or automated system were
tricked into opening a specially crafted Matroska, MOD, Real, or Real
Audio file, an attacker could execute arbitrary code as the user
invoking the program. This issue only applied to Ubuntu 6.06 LTS,
7.10, and 8.04 LTS. (CVE-2008-5238)

It was discovered that the input handlers in xine-lib did not
correctly handle certain error codes, resulting in out-of-bounds reads
and heap-based buffer overflows. If a user or automated system were
tricked into opening a specially crafted file, stream, or URL, an
attacker could execute arbitrary code as the user invoking the
program. (CVE-2008-5239)

It was discovered that the Matroska and Real demuxers in xine-lib did
not correctly handle memory allocation failures. If a user or
automated system were tricked into opening a specially crafted
Matroska or Real file, an attacker could crash xine-lib or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2008-5240)

It was discovered that the QT demuxer in xine-lib did not correctly
handle an invalid metadata atom size in a compressed MOV file,
resulting in an integer underflow. If a user or automated system were
tricked into opening a specially crafted MOV file, an attacker could
an attacker could cause xine-lib to crash, creating a denial of
service. (CVE-2008-5241)

It was discovered that the Real demuxer in xine-lib did not correctly
handle certain malformed files. If a user or automated system were
tricked into opening a specially crafted Real file, an attacker could
could cause xine-lib to crash, creating a denial of service.
(CVE-2008-5243)

It was discovered that xine-lib did not correctly handle certain
malformed AAC files. If a user or automated system were tricked into
opening a specially crafted AAC file, an attacker could could cause
xine-lib to crash, creating a denial of service. This issue only
applied to Ubuntu 7.10, and 8.04 LTS. (CVE-2008-5244)

It was discovered that the id3 tag handler in xine-lib did not
correctly handle malformed tags, resulting in heap-based buffer
overflows. If a user or automated system were tricked into opening a
media file containing a specially crafted id3 tag, an attacker could
execute arbitrary code as the user invoking the program. This issue
only applied to Ubuntu 6.06 LTS, 7.10, and 8.04 LTS. (CVE-2008-5246)

It was discovered that xine-lib did not correctly handle MP3 files
with metadata consisting only of separators. If a user or automated
system were tricked into opening a specially crafted MP3 file, an
attacker could could cause xine-lib to crash, creating a denial of
service. This issue only applied to Ubuntu 6.06 LTS, 7.10, and 8.04
LTS. (CVE-2008-5248)

It was discovered that the Matroska demuxer in xine-lib did not
correctly handle an invalid track type. If a user or automated system
were tricked into opening a specially crafted Matroska file, an
attacker could could cause xine-lib to crash, creating a denial of
service.

It was discovered that the ffmpeg video decoder in xine-lib did not
correctly handle media with certain image heights, resulting in a
heap-based buffer overflow. If a user or automated system were tricked
into opening a specially crafted video file, an attacker could crash
xine-lib or possibly execute arbitrary code with the privileges of the
user invoking the program. This issue only applied to Ubuntu 7.10,
8.04 LTS, and 8.10.

It was discovered that the ffmpeg audio decoder in xine-lib did not
correctly handle malformed media, resulting in a integer overflow. If
a user or automated system were tricked into opening a specially
crafted media file, an attacker could crash xine-lib or possibly
execute arbitrary code with the privileges of the user invoking the
program. This issue only applied to Ubuntu 8.10.

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
  script_cwe_id(20, 119, 189);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/26");
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

if (ubuntu_check(osver:"6.06", pkgname:"libxine-dev", pkgver:"1.1.1+ubuntu2-7.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxine-main1", pkgver:"1.1.1+ubuntu2-7.10")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine-dev", pkgver:"1.1.7-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1", pkgver:"1.1.7-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-console", pkgver:"1.1.7-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-dbg", pkgver:"1.1.7-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-doc", pkgver:"1.1.7-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-ffmpeg", pkgver:"1.1.7-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-gnome", pkgver:"1.1.7-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-plugins", pkgver:"1.1.7-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine-dev", pkgver:"1.1.11.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1", pkgver:"1.1.11.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-all-plugins", pkgver:"1.1.11.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-bin", pkgver:"1.1.11.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-console", pkgver:"1.1.11.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-dbg", pkgver:"1.1.11.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-doc", pkgver:"1.1.11.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-ffmpeg", pkgver:"1.1.11.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-gnome", pkgver:"1.1.11.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-misc-plugins", pkgver:"1.1.11.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-plugins", pkgver:"1.1.11.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-x", pkgver:"1.1.11.1-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine-dev", pkgver:"1.1.15-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1", pkgver:"1.1.15-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-all-plugins", pkgver:"1.1.15-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-bin", pkgver:"1.1.15-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-console", pkgver:"1.1.15-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-dbg", pkgver:"1.1.15-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-doc", pkgver:"1.1.15-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-ffmpeg", pkgver:"1.1.15-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-gnome", pkgver:"1.1.15-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-misc-plugins", pkgver:"1.1.15-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-plugins", pkgver:"1.1.15-0ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libxine1-x", pkgver:"1.1.15-0ubuntu3.1")) flag++;

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
