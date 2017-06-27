#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-635-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33940);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2008-0073", "CVE-2008-0225", "CVE-2008-0238", "CVE-2008-0486", "CVE-2008-1110", "CVE-2008-1161", "CVE-2008-1482", "CVE-2008-1686", "CVE-2008-1878");
  script_osvdb_id(42195, 42196, 42197, 42658, 43119, 43436, 43527, 43528, 43529, 43530, 43531, 43532, 44143, 44450);
  script_xref(name:"USN", value:"635-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 / 8.04 LTS : xine-lib vulnerabilities (USN-635-1)");
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
"Alin Rad Pop discovered an array index vulnerability in the SDP
parser. If a user or automated system were tricked into opening a
malicious RTSP stream, a remote attacker may be able to execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2008-0073)

Luigi Auriemma discovered that xine-lib did not properly check buffer
sizes in the RTSP header-handling code. If xine-lib opened an RTSP
stream with crafted SDP attributes, a remote attacker may be able to
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2008-0225, CVE-2008-0238)

Damian Frizza and Alfredo Ortega discovered that xine-lib did not
properly validate FLAC tags. If a user or automated system were
tricked into opening a crafted FLAC file, a remote attacker may be
able to execute arbitrary code with the privileges of the user
invoking the program. (CVE-2008-0486)

It was discovered that the ASF demuxer in xine-lib did not properly
check the length if the ASF header. If a user or automated system were
tricked into opening a crafted ASF file, a remote attacker could cause
a denial of service or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2008-1110)

It was discovered that the Matroska demuxer in xine-lib did not
properly verify frame sizes. If xine-lib opened a crafted ASF file, a
remote attacker could cause a denial of service or possibly execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2008-1161)

Luigi Auriemma discovered multiple integer overflows in xine-lib. If a
user or automated system were tricked into opening a crafted FLV, MOV,
RM, MVE, MKV or CAK file, a remote attacker may be able to execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2008-1482)

It was discovered that xine-lib did not properly validate its input
when processing Speex file headers. If a user or automated system were
tricked into opening a specially crafted Speex file, an attacker could
create a denial of service or possibly execute arbitrary code as the
user invoking the program. (CVE-2008-1686)

Guido Landi discovered a stack-based buffer overflow in xine-lib when
processing NSF files. If xine-lib opened a specially crafted NSF file
with a long NSF title, an attacker could create a denial of service or
possibly execute arbitrary code as the user invoking the program.
(CVE-2008-1878).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine-extracodecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine-main1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-all-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-misc-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxine1-x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/20");
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

if (ubuntu_check(osver:"6.06", pkgname:"libxine-dev", pkgver:"1.1.1+ubuntu2-7.9")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxine-main1", pkgver:"1.1.1+ubuntu2-7.9")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxine-dev", pkgver:"1.1.4-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxine-extracodecs", pkgver:"1.1.4-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxine-main1", pkgver:"1.1.4-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxine1", pkgver:"1.1.4-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxine1-console", pkgver:"1.1.4-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxine1-dbg", pkgver:"1.1.4-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxine1-ffmpeg", pkgver:"1.1.4-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxine1-gnome", pkgver:"1.1.4-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxine1-kde", pkgver:"1.1.4-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxine1-plugins", pkgver:"1.1.4-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine-dev", pkgver:"1.1.7-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1", pkgver:"1.1.7-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-console", pkgver:"1.1.7-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-dbg", pkgver:"1.1.7-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-doc", pkgver:"1.1.7-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-ffmpeg", pkgver:"1.1.7-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-gnome", pkgver:"1.1.7-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxine1-plugins", pkgver:"1.1.7-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine-dev", pkgver:"1.1.11.1-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1", pkgver:"1.1.11.1-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-all-plugins", pkgver:"1.1.11.1-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-bin", pkgver:"1.1.11.1-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-console", pkgver:"1.1.11.1-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-dbg", pkgver:"1.1.11.1-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-doc", pkgver:"1.1.11.1-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-ffmpeg", pkgver:"1.1.11.1-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-gnome", pkgver:"1.1.11.1-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-misc-plugins", pkgver:"1.1.11.1-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-plugins", pkgver:"1.1.11.1-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxine1-x", pkgver:"1.1.11.1-1ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxine-dev / libxine-extracodecs / libxine-main1 / libxine1 / etc");
}
