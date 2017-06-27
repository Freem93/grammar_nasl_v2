#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1045-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51584);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2010-3879");
  script_osvdb_id(70520);
  script_xref(name:"USN", value:"1045-2");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : util-linux update (USN-1045-2)");
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
"USN-1045-1 fixed vulnerabilities in FUSE. This update to util-linux
adds support for new options required by the FUSE update.

It was discovered that FUSE could be tricked into incorrectly updating
the mtab file when mounting filesystems. A local attacker, with access
to use FUSE, could unmount arbitrary locations, leading to a denial of
service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bsdutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libblkid-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:util-linux-locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uuid-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uuid-runtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"bsdutils", pkgver:"2.13.1-5ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mount", pkgver:"2.13.1-5ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"util-linux", pkgver:"2.13.1-5ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"util-linux-locales", pkgver:"2.13.1-5ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"bsdutils", pkgver:"2.16-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libblkid-dev", pkgver:"2.16-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libblkid1", pkgver:"2.16-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libuuid1", pkgver:"2.16-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mount", pkgver:"2.16-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"util-linux", pkgver:"2.16-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"util-linux-locales", pkgver:"2.16-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"uuid-dev", pkgver:"2.16-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"uuid-runtime", pkgver:"2.16-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"bsdutils", pkgver:"2.17.2-0ubuntu1.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libblkid-dev", pkgver:"2.17.2-0ubuntu1.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libblkid1", pkgver:"2.17.2-0ubuntu1.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libuuid1", pkgver:"2.17.2-0ubuntu1.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mount", pkgver:"2.17.2-0ubuntu1.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"util-linux", pkgver:"2.17.2-0ubuntu1.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"util-linux-locales", pkgver:"2.17.2-0ubuntu1.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"uuid-dev", pkgver:"2.17.2-0ubuntu1.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"uuid-runtime", pkgver:"2.17.2-0ubuntu1.10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"bsdutils", pkgver:"2.17.2-0ubuntu1.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libblkid-dev", pkgver:"2.17.2-0ubuntu1.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libblkid1", pkgver:"2.17.2-0ubuntu1.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libuuid1", pkgver:"2.17.2-0ubuntu1.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"mount", pkgver:"2.17.2-0ubuntu1.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"util-linux", pkgver:"2.17.2-0ubuntu1.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"util-linux-locales", pkgver:"2.17.2-0ubuntu1.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"uuid-dev", pkgver:"2.17.2-0ubuntu1.10.10.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"uuid-runtime", pkgver:"2.17.2-0ubuntu1.10.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bsdutils / libblkid-dev / libblkid1 / libuuid1 / mount / util-linux / etc");
}
