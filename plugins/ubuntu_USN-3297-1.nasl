#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3297-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100413);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/25 13:29:27 $");

  script_cve_id("CVE-2016-9601", "CVE-2017-7885", "CVE-2017-7975", "CVE-2017-7976");
  script_xref(name:"USN", value:"3297-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 16.10 / 17.04 : jbig2dec vulnerabilities (USN-3297-1)");
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
"Bingchang Liu discovered that jbig2dec incorrectly handled memory when
decoding malformed image files. If a user or automated system were
tricked into processing a specially crafted JBIG2 image file, a remote
attacker could cause jbig2dec to crash, resulting in a denial of
service, or possibly execute arbitrary code. This issue only applied
to Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10.
(CVE-2016-9601)

It was discovered that jbig2dec incorrectly handled memory when
decoding malformed image files. If a user or automated system were
tricked into processing a specially crafted JBIG2 image file, a remote
attacker could cause jbig2dec to crash, resulting in a denial of
service, or possibly disclose sensitive information. (CVE-2017-7885)

Jiaqi Peng discovered that jbig2dec incorrectly handled memory when
decoding malformed image files. If a user or automated system were
tricked into processing a specially crafted JBIG2 image file, a remote
attacker could cause jbig2dec to crash, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2017-7975)

Dai Ge discovered that jbig2dec incorrectly handled memory when
decoding malformed image files. If a user or automated system were
tricked into processing a specially crafted JBIG2 image file, a remote
attacker could cause jbig2dec to crash, resulting in a denial of
service, or possibly disclose sensitive information. (CVE-2017-7976).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jbig2dec and / or libjbig2dec0 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:jbig2dec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjbig2dec0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04|16\.04|16\.10|17\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 16.10 / 17.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"jbig2dec", pkgver:"0.11+20120125-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libjbig2dec0", pkgver:"0.11+20120125-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"jbig2dec", pkgver:"0.12+20150918-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libjbig2dec0", pkgver:"0.12+20150918-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"jbig2dec", pkgver:"0.13-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libjbig2dec0", pkgver:"0.13-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"jbig2dec", pkgver:"0.13-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"libjbig2dec0", pkgver:"0.13-4ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jbig2dec / libjbig2dec0");
}
