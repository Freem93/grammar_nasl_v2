#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-176-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20586);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:21:16 $");

  script_cve_id("CVE-2005-2494");
  script_xref(name:"USN", value:"176-1");

  script_name(english:"Ubuntu 5.04 : kdebase vulnerability (USN-176-1)");
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
"Ilja van Sprundel discovered a flaw in the lock file handling of
kcheckpass. A local attacker could exploit this to execute arbitrary
code with root privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kappfinder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kcontrol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdebase-kio-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdepasswd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdeprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdesktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kfind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:khelpcenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kicker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:klipper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kmenuedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:konqueror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:konqueror-nsplugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:konsole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpersonalizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ksmserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ksplash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ksysguard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ksysguardd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ktip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kwin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkonq4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkonq4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-konsole");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"5.04", pkgname:"kappfinder", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kate", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kcontrol", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdebase", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdebase-bin", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdebase-data", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdebase-dev", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdebase-doc", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdebase-kio-plugins", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdepasswd", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdeprint", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdesktop", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdm", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kfind", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"khelpcenter", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kicker", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"klipper", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kmenuedit", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"konqueror", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"konqueror-nsplugins", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"konsole", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kpager", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kpersonalizer", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ksmserver", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ksplash", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ksysguard", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ksysguardd", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ktip", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kwin", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkonq4", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkonq4-dev", pkgver:"3.4.0-0ubuntu18.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xfonts-konsole", pkgver:"3.4.0-0ubuntu18.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kappfinder / kate / kcontrol / kdebase / kdebase-bin / kdebase-data / etc");
}
