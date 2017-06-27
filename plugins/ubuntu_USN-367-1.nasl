#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-367-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27947);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:21:18 $");

  script_cve_id("CVE-2006-4041");
  script_osvdb_id(26238);
  script_xref(name:"USN", value:"367-1");

  script_name(english:"Ubuntu 5.04 : pike7.6 vulnerability (USN-367-1)");
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
"A SQL injection was discovered in Pike's PostgreSQL module.
Applications using a PostgreSQL database and uncommon character
encodings could be fooled into running arbitrary SQL commands, which
could result in privilege escalation within the application,
application data exposure, or denial of service.

Please refer to http://www.ubuntu.com/usn/usn-288-1 for more detailled
information.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-pcre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-reference");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-sane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pike7.6-svg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/06");
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
if (! ereg(pattern:"^(5\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"pike7.6", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-bzip2", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-core", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-dev", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-doc", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-gdbm", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-gl", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-gtk", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-image", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-manual", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-meta", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-mysql", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-odbc", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-pcre", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-perl", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-pg", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-reference", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-sane", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-sdl", pkgver:"7.6.13-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pike7.6-svg", pkgver:"7.6.13-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pike7.6 / pike7.6-bzip2 / pike7.6-core / pike7.6-dev / pike7.6-doc / etc");
}
