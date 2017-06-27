#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2054-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71376);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/25 16:34:54 $");

  script_cve_id("CVE-2012-6150", "CVE-2013-4408", "CVE-2013-4475");
  script_bugtraq_id(63646, 64101, 64191);
  script_osvdb_id(99705, 100749, 102653);
  script_xref(name:"USN", value:"2054-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 12.10 / 13.04 / 13.10 : samba vulnerabilities (USN-2054-1)");
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
"It was discovered that Winbind incorrectly handled invalid group names
with the require_membership_of parameter. If an administrator used an
invalid group name by mistake, access was granted instead of having
the login fail. (CVE-2012-6150)

Stefan Metzmacher and Michael Adam discovered that Samba incorrectly
handled DCE-RPC fragment length fields. A remote attacker could use
this issue to cause Samba to crash, resulting in a denial of service,
or possibly execute arbitrary code as the root user. (CVE-2013-4408)

Hemanth Thummala discovered that Samba incorrectly handled file
permissions when vfs_streams_depot or vfs_streams_xattr were enabled.
A remote attacker could use this issue to bypass intended
restrictions. (CVE-2013-4475).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpam-winbind, samba and / or winbind packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|12\.04|12\.10|13\.04|13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 12.10 / 13.04 / 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"samba", pkgver:"2:3.4.7~dfsg-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"winbind", pkgver:"2:3.4.7~dfsg-1ubuntu3.13")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libpam-winbind", pkgver:"2:3.6.3-2ubuntu2.9")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"samba", pkgver:"2:3.6.3-2ubuntu2.9")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libpam-winbind", pkgver:"2:3.6.6-3ubuntu5.3")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"samba", pkgver:"2:3.6.6-3ubuntu5.3")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"libpam-winbind", pkgver:"2:3.6.9-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"samba", pkgver:"2:3.6.9-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"libpam-winbind", pkgver:"2:3.6.18-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"samba", pkgver:"2:3.6.18-1ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpam-winbind / samba / winbind");
}
