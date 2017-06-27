#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1016-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50560);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2010-4008");
  script_osvdb_id(69205);
  script_xref(name:"USN", value:"1016-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : libxml2 vulnerability (USN-1016-1)");
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
"Bui Quang Minh discovered that libxml2 did not properly process XPath
namespaces and attributes. If an application using libxml2 opened a
specially crafted XML file, an attacker could cause a denial of
service or possibly execute code as the user invoking the program.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/11");
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
if (! ereg(pattern:"^(6\.06|8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libxml2", pkgver:"2.6.24.dfsg-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxml2-dbg", pkgver:"2.6.24.dfsg-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxml2-dev", pkgver:"2.6.24.dfsg-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxml2-doc", pkgver:"2.6.24.dfsg-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxml2-utils", pkgver:"2.6.24.dfsg-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python-libxml2", pkgver:"2.6.24.dfsg-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-libxml2", pkgver:"2.6.24.dfsg-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxml2", pkgver:"2.6.31.dfsg-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxml2-dbg", pkgver:"2.6.31.dfsg-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxml2-dev", pkgver:"2.6.31.dfsg-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxml2-doc", pkgver:"2.6.31.dfsg-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxml2-utils", pkgver:"2.6.31.dfsg-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-libxml2", pkgver:"2.6.31.dfsg-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-libxml2-dbg", pkgver:"2.6.31.dfsg-2ubuntu1.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libxml2", pkgver:"2.7.5.dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libxml2-dbg", pkgver:"2.7.5.dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libxml2-dev", pkgver:"2.7.5.dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libxml2-doc", pkgver:"2.7.5.dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libxml2-utils", pkgver:"2.7.5.dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-libxml2", pkgver:"2.7.5.dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-libxml2-dbg", pkgver:"2.7.5.dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libxml2", pkgver:"2.7.6.dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libxml2-dbg", pkgver:"2.7.6.dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libxml2-dev", pkgver:"2.7.6.dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libxml2-doc", pkgver:"2.7.6.dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libxml2-utils", pkgver:"2.7.6.dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"python-libxml2", pkgver:"2.7.6.dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"python-libxml2-dbg", pkgver:"2.7.6.dfsg-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libxml2", pkgver:"2.7.7.dfsg-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libxml2-dbg", pkgver:"2.7.7.dfsg-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libxml2-dev", pkgver:"2.7.7.dfsg-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libxml2-doc", pkgver:"2.7.7.dfsg-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libxml2-utils", pkgver:"2.7.7.dfsg-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"python-libxml2", pkgver:"2.7.7.dfsg-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"python-libxml2-dbg", pkgver:"2.7.7.dfsg-4ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-dbg / libxml2-dev / libxml2-doc / libxml2-utils / etc");
}
