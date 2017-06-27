#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-872-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43153);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:45:43 $");

  script_osvdb_id(61174, 61175);
  script_xref(name:"USN", value:"872-1");

  script_name(english:"Ubuntu 8.10 / 9.04 / 9.10 : kdebase-runtime vulnerabilities (USN-872-1)");
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
"It was discovered that the KIO subsystem of KDE did not properly
perform input validation when processing help:// URIs. If a user or
KIO application processed a crafted help:// URI, an attacker could
trigger JavaScript execution or access files via directory traversal.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kde-icons-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-runtime-bin-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-runtime-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-runtime-data-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-runtime-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:khelpcenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:khelpcenter4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:phonon-backend-xine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:plasma-scriptengine-javascript");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/14");
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

if (ubuntu_check(osver:"8.10", pkgname:"kde-icons-oxygen", pkgver:"4.1.4-0ubuntu1~intrepid1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdebase-runtime", pkgver:"4:4.1.4-0ubuntu1~intrepid1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdebase-runtime-bin-kde4", pkgver:"4.1.4-0ubuntu1~intrepid1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdebase-runtime-data", pkgver:"4.1.4-0ubuntu1~intrepid1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdebase-runtime-data-common", pkgver:"4.1.4-0ubuntu1~intrepid1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdebase-runtime-dbg", pkgver:"4.1.4-0ubuntu1~intrepid1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"khelpcenter", pkgver:"4.1.4-0ubuntu1~intrepid1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"khelpcenter4", pkgver:"4.1.4-0ubuntu1~intrepid1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"phonon-backend-xine", pkgver:"4.1.4-0ubuntu1~intrepid1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kde-icons-oxygen", pkgver:"4.2.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdebase-runtime", pkgver:"4:4.2.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdebase-runtime-bin-kde4", pkgver:"4.2.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdebase-runtime-data", pkgver:"4.2.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdebase-runtime-data-common", pkgver:"4.2.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"kdebase-runtime-dbg", pkgver:"4.2.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"khelpcenter", pkgver:"4.2.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"khelpcenter4", pkgver:"4.2.2-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdebase-runtime", pkgver:"4:4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdebase-runtime-bin-kde4", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdebase-runtime-data", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdebase-runtime-data-common", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"kdebase-runtime-dbg", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"khelpcenter", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"khelpcenter4", pkgver:"4.3.2-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"plasma-scriptengine-javascript", pkgver:"4.3.2-0ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kde-icons-oxygen / kdebase-runtime / kdebase-runtime-bin-kde4 / etc");
}
