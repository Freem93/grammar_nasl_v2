#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-871-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43110);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:45:43 $");

  script_osvdb_id(60913);
  script_xref(name:"USN", value:"871-2");

  script_name(english:"Ubuntu 8.10 / 9.04 / 9.10 : kde4libs vulnerabilities (USN-871-2)");
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
"USN-871-1 fixed vulnerabilities in KDE. This update provides the
corresponding updates for KDE 4.

This update also fixes a directory traversal flaw in KDE when
processing help:// URLs. This issue only affected Ubuntu 8.10.

It was discovered that the KDE libraries could use KHTML to process an
unknown MIME type. If a user or application linked against kdelibs
were tricked into opening a crafted file, an attacker could
potentially trigger XMLHTTPRequests to remote sites.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs5-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libplasma-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libplasma3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/11");
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
if (! ereg(pattern:"^(8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.10", pkgname:"kdelibs-bin", pkgver:"4.1.4-0ubuntu1~intrepid1.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs5", pkgver:"4:4.1.4-0ubuntu1~intrepid1.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs5-data", pkgver:"4.1.4-0ubuntu1~intrepid1.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs5-dbg", pkgver:"4.1.4-0ubuntu1~intrepid1.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs5-dev", pkgver:"4.1.4-0ubuntu1~intrepid1.5")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdelibs5-doc", pkgver:"4.1.4-0ubuntu1~intrepid1.5")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdelibs-bin", pkgver:"4.2.2-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdelibs5", pkgver:"4:4.2.2-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdelibs5-data", pkgver:"4.2.2-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdelibs5-dbg", pkgver:"4.2.2-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdelibs5-dev", pkgver:"4.2.2-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libplasma-dev", pkgver:"4.2.2-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libplasma3", pkgver:"4.2.2-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdelibs-bin", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdelibs5", pkgver:"4:4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdelibs5-data", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdelibs5-dbg", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdelibs5-dev", pkgver:"4.3.2-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libplasma3", pkgver:"4.3.2-0ubuntu7.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs-bin / kdelibs5 / kdelibs5-data / kdelibs5-dbg / etc");
}
