#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-363-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27943);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:21:18 $");

  script_cve_id("CVE-2006-4197");
  script_osvdb_id(27944, 27945);
  script_xref(name:"USN", value:"363-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : libmusicbrainz-2.0, libmusicbrainz-2.1 vulnerability (USN-363-1)");
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
"Luigi Auriemma discovered multiple buffer overflows in libmusicbrainz.
When a user made queries to MusicBrainz servers, it was possible for
malicious servers, or man-in-the-middle systems posing as servers, to
send a crafted reply to the client request and remotely gain access to
the user's system with the user's privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmusicbrainz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmusicbrainz2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmusicbrainz2c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmusicbrainz4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmusicbrainz4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmusicbrainz4c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmusicbrainz4c2a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-musicbrainz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-musicbrainz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-musicbrainz");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/13");
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

if (ubuntu_check(osver:"5.04", pkgname:"libmusicbrainz2", pkgver:"2.0.2-10ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmusicbrainz2-dev", pkgver:"2.0.2-10ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmusicbrainz4", pkgver:"2.1.1-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libmusicbrainz4-dev", pkgver:"2.1.1-3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python-musicbrainz", pkgver:"2.0.2-10ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3-musicbrainz", pkgver:"2.0.2-10ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.4-musicbrainz", pkgver:"2.0.2-10ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmusicbrainz2-dev", pkgver:"2.0.2-10ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmusicbrainz2c2", pkgver:"2.0.2-10ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmusicbrainz4-dev", pkgver:"2.1.1-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libmusicbrainz4c2", pkgver:"2.1.1-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python-musicbrainz", pkgver:"2.0.2-10ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.3-musicbrainz", pkgver:"2.0.2-10ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.4-musicbrainz", pkgver:"2.0.2-10ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmusicbrainz4-dev", pkgver:"2.1.2-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmusicbrainz4c2a", pkgver:"2.1.2-2ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmusicbrainz2 / libmusicbrainz2-dev / libmusicbrainz2c2 / etc");
}
