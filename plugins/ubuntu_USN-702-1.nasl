#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-702-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37362);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:37:18 $");

  script_cve_id("CVE-2009-0022");
  script_xref(name:"USN", value:"702-1");

  script_name(english:"Ubuntu 8.10 : samba vulnerability (USN-702-1)");
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
"Gunter Hockel discovered that Samba with registry shares enabled did
not properly validate share names. An authenticated user could gain
access to the root filesystem by using an older version of smbclient
and specifying an empty string as a share name. This is only an issue
if registry shares are enabled on the server by setting 'registry
shares = yes', 'include = registry', or 'config backend = registry',
which is not the default.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:N/A:N");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-smbpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:smbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:smbfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (! ereg(pattern:"^(8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.10", pkgname:"libpam-smbpass", pkgver:"3.2.3-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsmbclient", pkgver:"3.2.3-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsmbclient-dev", pkgver:"3.2.3-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libwbclient0", pkgver:"3.2.3-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"samba", pkgver:"2:3.2.3-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"samba-common", pkgver:"3.2.3-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"samba-dbg", pkgver:"3.2.3-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"samba-doc", pkgver:"3.2.3-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"samba-doc-pdf", pkgver:"3.2.3-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"samba-tools", pkgver:"3.2.3-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"smbclient", pkgver:"3.2.3-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"smbfs", pkgver:"3.2.3-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"swat", pkgver:"3.2.3-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"winbind", pkgver:"3.2.3-1ubuntu3.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpam-smbpass / libsmbclient / libsmbclient-dev / libwbclient0 / etc");
}
