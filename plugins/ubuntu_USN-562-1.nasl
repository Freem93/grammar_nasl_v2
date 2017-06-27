#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-562-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29918);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:29:18 $");

  script_cve_id("CVE-2007-4924");
  script_osvdb_id(41637);
  script_xref(name:"USN", value:"562-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 : opal vulnerability (USN-562-1)");
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
"Jose Miguel Esparza discovered that certain SIP headers were not
correctly validated. A remote attacker could send a specially crafted
packet to an application linked against opal (e.g. Ekiga) causing it
to crash, leading to a denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopal-2.2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopal-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopal-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopal-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:simpleopal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/10");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libopal-2.2.0", pkgver:"2.2.1-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libopal-dbg", pkgver:"2.2.1-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libopal-dev", pkgver:"2.2.1-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libopal-doc", pkgver:"2.2.1-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"simpleopal", pkgver:"2.2.1-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libopal-2.2.0", pkgver:"2.2.3.dfsg-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libopal-dbg", pkgver:"2.2.3.dfsg-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libopal-dev", pkgver:"2.2.3.dfsg-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libopal-doc", pkgver:"2.2.3.dfsg-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"simpleopal", pkgver:"2.2.3.dfsg-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libopal-2.2.0", pkgver:"2.2.3.dfsg-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libopal-dbg", pkgver:"2.2.3.dfsg-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libopal-dev", pkgver:"2.2.3.dfsg-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libopal-doc", pkgver:"2.2.3.dfsg-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"simpleopal", pkgver:"2.2.3.dfsg-2ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopal-2.2.0 / libopal-dbg / libopal-dev / libopal-doc / etc");
}
