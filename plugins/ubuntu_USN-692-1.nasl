#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-692-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36984);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:37:17 $");

  script_cve_id("CVE-2008-4776");
  script_xref(name:"USN", value:"692-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : ekg, libgadu vulnerability (USN-692-1)");
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
"It was discovered that the Gadu library, used by some Instant
Messaging clients, did not correctly verify certain packet sizes from
the server. If a user connected to a malicious server, clients using
Gadu could be made to crash, leading to a denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ekg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgadu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgadu3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgadu3-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"6.06", pkgname:"ekg", pkgver:"1.6+20051103-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgadu-dev", pkgver:"1.6+20051103-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgadu3", pkgver:"1:1.6+20051103-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ekg", pkgver:"1.7~rc2-2ubuntu0.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libgadu-dev", pkgver:"1.7~rc2-2ubuntu0.7.10.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libgadu3", pkgver:"1:1.7~rc2-2ubuntu0.7.10.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ekg", pkgver:"1.7~rc2-2ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgadu-dev", pkgver:"1.7~rc2-2ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgadu3", pkgver:"1:1.7~rc2-2ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgadu-dev", pkgver:"1.8.0+r592-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgadu3", pkgver:"1:1.8.0+r592-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgadu3-dbg", pkgver:"1.8.0+r592-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ekg / libgadu-dev / libgadu3 / libgadu3-dbg");
}
