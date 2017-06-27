#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-580-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31165);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:29:19 $");

  script_cve_id("CVE-2007-6613");
  script_osvdb_id(42742);
  script_xref(name:"USN", value:"580-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : libcdio vulnerability (USN-580-1)");
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
"Devon Miller discovered that the iso-info and cd-info tools did not
properly perform bounds checking. If a user were tricked into using
these tools with a crafted iso image, an attacker could cause a denial
of service (core dump) and possibly execute arbitrary code.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio-cdda-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio-cdda0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio-paranoia-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio-paranoia0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcdio6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libiso9660-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libiso9660-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/25");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libcdio-cdda-dev", pkgver:"0.76-1ubuntu1.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcdio-cdda0", pkgver:"0.76-1ubuntu1.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcdio-dev", pkgver:"0.76-1ubuntu1.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcdio-paranoia-dev", pkgver:"0.76-1ubuntu1.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcdio-paranoia0", pkgver:"0.76-1ubuntu1.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcdio6", pkgver:"0.76-1ubuntu1.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libiso9660-4", pkgver:"0.76-1ubuntu1.6.06.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libiso9660-dev", pkgver:"0.76-1ubuntu1.6.06.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcdio-cdda-dev", pkgver:"0.76-1ubuntu1.6.10.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcdio-cdda0", pkgver:"0.76-1ubuntu1.6.10.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcdio-dev", pkgver:"0.76-1ubuntu1.6.10.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcdio-paranoia-dev", pkgver:"0.76-1ubuntu1.6.10.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcdio-paranoia0", pkgver:"0.76-1ubuntu1.6.10.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcdio6", pkgver:"0.76-1ubuntu1.6.10.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libiso9660-4", pkgver:"0.76-1ubuntu1.6.10.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libiso9660-dev", pkgver:"0.76-1ubuntu1.6.10.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcdio-cdda-dev", pkgver:"0.76-1ubuntu2.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcdio-cdda0", pkgver:"0.76-1ubuntu2.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcdio-dev", pkgver:"0.76-1ubuntu2.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcdio-paranoia-dev", pkgver:"0.76-1ubuntu2.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcdio-paranoia0", pkgver:"0.76-1ubuntu2.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcdio6", pkgver:"0.76-1ubuntu2.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libiso9660-4", pkgver:"0.76-1ubuntu2.7.04.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libiso9660-dev", pkgver:"0.76-1ubuntu2.7.04.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcdio-cdda-dev", pkgver:"0.76-1ubuntu2.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcdio-cdda0", pkgver:"0.76-1ubuntu2.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcdio-dev", pkgver:"0.76-1ubuntu2.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcdio-paranoia-dev", pkgver:"0.76-1ubuntu2.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcdio-paranoia0", pkgver:"0.76-1ubuntu2.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcdio6", pkgver:"0.76-1ubuntu2.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libiso9660-4", pkgver:"0.76-1ubuntu2.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libiso9660-dev", pkgver:"0.76-1ubuntu2.7.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcdio-cdda-dev / libcdio-cdda0 / libcdio-dev / etc");
}