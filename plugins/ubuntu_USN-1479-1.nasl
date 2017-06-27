#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1479-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59566);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/25 16:19:24 $");

  script_cve_id("CVE-2011-3929", "CVE-2011-3936", "CVE-2011-3940", "CVE-2011-3947", "CVE-2011-3951", "CVE-2011-3952", "CVE-2012-0851", "CVE-2012-0852", "CVE-2012-0853", "CVE-2012-0858", "CVE-2012-0859", "CVE-2012-0947");
  script_bugtraq_id(51307, 51720, 53389);
  script_osvdb_id(78178, 78635, 78636, 78641, 78644, 78645, 78648, 82114, 82128, 82132, 83116);
  script_xref(name:"USN", value:"1479-1");

  script_name(english:"Ubuntu 10.04 LTS : ffmpeg vulnerabilities (USN-1479-1)");
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
"Mateusz Jurczyk and Gynvael Coldwind discovered that FFmpeg
incorrectly handled certain malformed DV files. If a user were tricked
into opening a crafted DV file, an attacker could cause a denial of
service via application crash, or possibly execute arbitrary code with
the privileges of the user invoking the program. (CVE-2011-3929,
CVE-2011-3936)

Mateusz Jurczyk and Gynvael Coldwind discovered that FFmpeg
incorrectly handled certain malformed NSV files. If a user were
tricked into opening a crafted NSV file, an attacker could cause a
denial of service via application crash, or possibly execute arbitrary
code with the privileges of the user invoking the program.
(CVE-2011-3940)

Mateusz Jurczyk and Gynvael Coldwind discovered that FFmpeg
incorrectly handled certain malformed MJPEG-B files. If a user were
tricked into opening a crafted MJPEG-B file, an attacker could cause a
denial of service via application crash, or possibly execute arbitrary
code with the privileges of the user invoking the program.
(CVE-2011-3947)

Mateusz Jurczyk and Gynvael Coldwind discovered that FFmpeg
incorrectly handled certain malformed DPCM files. If a user were
tricked into opening a crafted DPCM file, an attacker could cause a
denial of service via application crash, or possibly execute arbitrary
code with the privileges of the user invoking the program.
(CVE-2011-3951)

Mateusz Jurczyk and Gynvael Coldwind discovered that FFmpeg
incorrectly handled certain malformed KMVC files. If a user were
tricked into opening a crafted KMVC file, an attacker could cause a
denial of service via application crash, or possibly execute arbitrary
code with the privileges of the user invoking the program.
(CVE-2011-3952)

It was discovered that FFmpeg incorrectly handled certain malformed
H.264 files. If a user were tricked into opening a crafted H.264 file,
an attacker could cause a denial of service via application crash, or
possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2012-0851)

It was discovered that FFmpeg incorrectly handled certain malformed
ADPCM files. If a user were tricked into opening a crafted ADPCM file,
an attacker could cause a denial of service via application crash, or
possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2012-0852)

It was discovered that FFmpeg incorrectly handled certain malformed
Atrac 3 files. If a user were tricked into opening a crafted Atrac 3
file, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2012-0853)

It was discovered that FFmpeg incorrectly handled certain malformed
Shorten files. If a user were tricked into opening a crafted Shorten
file, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2012-0858)

It was discovered that FFmpeg incorrectly handled certain malformed
Vorbis files. If a user were tricked into opening a crafted Vorbis
file, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2012-0859)

Fabian Yamaguchi discovered that FFmpeg incorrectly handled certain
malformed VQA files. If a user were tricked into opening a crafted VQA
file, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2012-0947).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libavcodec52 and / or libavformat52 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat52");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2016 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libavcodec52", pkgver:"4:0.5.9-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libavformat52", pkgver:"4:0.5.9-0ubuntu0.10.04.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libavcodec52 / libavformat52");
}
