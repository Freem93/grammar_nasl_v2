#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-391-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27976);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/27 14:21:18 $");

  script_cve_id("CVE-2006-4514");
  script_bugtraq_id(21358);
  script_osvdb_id(31702);
  script_xref(name:"USN", value:"391-1");

  script_name(english:"Ubuntu 5.10 / 6.06 LTS / 6.10 : libgsf vulnerability (USN-391-1)");
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
"A heap overflow was discovered in the OLE processing code in libgsf.
If a user were tricked into opening a specially crafted OLE document,
an attacker could execute arbitrary code with the user's privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgsf-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgsf-1-113");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgsf-1-113-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgsf-1-114");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgsf-1-114-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgsf-1-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgsf-1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgsf-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgsf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgsf-gnome-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgsf-gnome-1-113");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgsf-gnome-1-113-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgsf-gnome-1-114");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgsf-gnome-1-114-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgsf-gnome-1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgsf-gnome-1-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/30");
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
if (! ereg(pattern:"^(5\.10|6\.06|6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.10 / 6.06 / 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.10", pkgname:"libgsf-1", pkgver:"1.12.3-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgsf-1-dbg", pkgver:"1.12.3-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgsf-1-dev", pkgver:"1.12.3-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgsf-gnome-1", pkgver:"1.12.3-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgsf-gnome-1-dbg", pkgver:"1.12.3-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgsf-gnome-1-dev", pkgver:"1.12.3-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgsf-1-113", pkgver:"1.13.99-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgsf-1-113-dbg", pkgver:"1.13.99-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgsf-1-common", pkgver:"1.13.99-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgsf-1-dev", pkgver:"1.13.99-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgsf-bin", pkgver:"1.13.99-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgsf-gnome-1-113", pkgver:"1.13.99-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgsf-gnome-1-113-dbg", pkgver:"1.13.99-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgsf-gnome-1-dev", pkgver:"1.13.99-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libgsf-1-114", pkgver:"1.14.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libgsf-1-114-dbg", pkgver:"1.14.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libgsf-1-common", pkgver:"1.14.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libgsf-1-dev", pkgver:"1.14.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libgsf-bin", pkgver:"1.14.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libgsf-gnome-1-114", pkgver:"1.14.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libgsf-gnome-1-114-dbg", pkgver:"1.14.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libgsf-gnome-1-dev", pkgver:"1.14.1-2ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgsf-1 / libgsf-1-113 / libgsf-1-113-dbg / libgsf-1-114 / etc");
}
